#!/usr/bin/env python3
import atexit
import copy
import datetime
import json
import logging
import math
import os
import pathlib
import random
import signal
import subprocess
import sys
import threading
import time
import traceback
from abc import abstractmethod
from collections import deque
from pathlib import Path
from typing import Deque, Dict, List, Optional

# FIXME
if __package__ is None:
    sys.path.append(
        os.path.dirname(os.path.dirname(os.path.realpath(__file__))))
    __package__ = "autofz"

from cgroupspy import trees
from rich.console import Console

from . import cgroup_utils, cli
from . import config as Config
from . import coverage, fuzzer_driver, fuzzing, policy, sync, utils
from .common import IS_DEBUG, IS_PROFILE, nested_dict
from .datatype import Bitmap
from .mytype import BitmapContribution, Coverage, Fuzzer, Fuzzers
from .singleton import SingletonABCMeta
from . import thompson 

config: Dict = Config.CONFIG

logger = logging.getLogger('autofz.main')

logging.basicConfig(level=logging.INFO, filename='testlogging.log', filemode='w', format ='%(asctime)s - %(filename)s - %(funcName)s - %(lineno)d - %(message)s')

console = Console()
LOG = nested_dict()

OUTPUT: Path
INPUT: Optional[Path]
LOG_DATETIME: str
LOG_FILE_NAME: str

# how much time to reschedule
PREP_TIME: int
FOCUS_TIME: int

SYNC_TIME: int

COVERAGE_UPDATE_TIME = config['scheduler']['coverage_update_time']

FUZZERS: Fuzzers = []

TARGET: str

CPU_ASSIGN: Dict[Fuzzer, float] = {}

JOBS = 1

ARGS: cli.ArgsParser

START_TIME: float = 0.0

SLEEP_GRANULARITY: int = 60

RUNNING: bool = False
# AUTOFZ_PID = os.getpid()

# CGROUP_PATH = '/sys/fs/cgroup/cpu/yufu'
CGROUP_ROOT = ''

# round robin vs paralle when using multi core
PARALLEL: bool = False


def terminate_autofz():
    global AUTOFZ_PID
    logger.critical('terminate autofz because of error')
    cleanup(1)


def check_fuzzer_ready_one(fuzzer):
    global ARGS, FUZZERS, TARGET, OUTPUT
    # NOTE: fuzzer driver will create a ready file when launcing
    ready_path = os.path.join(OUTPUT, TARGET, fuzzer, 'ready')
    if not os.path.exists(ready_path):
        return False
    return True


def check_fuzzer_ready():
    global ARGS, FUZZERS, TARGET, OUTPUT
    for fuzzer in FUZZERS:
        if ARGS.focus_one and fuzzer != ARGS.focus_one: continue
        # NOTE: fuzzer driver will create a ready file when launcing
        ready_path = os.path.join(OUTPUT, TARGET, fuzzer, 'ready')
        if not os.path.exists(ready_path):
            return False
    return True


def is_end():
    global START_TIME
    diff = 300
    current_time = time.time()
    elasp = current_time - START_TIME
    timeout_seconds = utils.time_to_seconds(ARGS.timeout)
    return elasp >= timeout_seconds + diff


def is_end_global():
    global START_TIME
    diff = 300
    current_time = time.time()
    elasp = current_time - START_TIME
    timeout_seconds = utils.time_to_seconds(ARGS.timeout)
    logger.debug(f'is end global: {current_time}, {START_TIME}, {elasp}')
    return elasp >= timeout_seconds + diff


def health_check_evaluator():
    return coverage.EVALUTOR_THREAD.is_alive()


def check_evaluator_seed_finished():
    seed_finished_file = os.path.join(ARGS.output, 'eval', 'seed-finished')
    return os.path.exists(seed_finished_file)


def thread_health_check():
    global ARGS
    health_check_path = os.path.realpath(os.path.join(ARGS.output, 'health'))
    while not is_end():
        if not health_check_evaluator():
            logger.critical('evaluator health check fail')
            terminate_autofz()
        pathlib.Path(health_check_path).touch(mode=0o666, exist_ok=True)
        time.sleep(60)


def sleep(seconds: int, log=False):
    logger.info(f'main 001 -  sleep time: {seconds}, log: {log}')
    '''
    hack to early return
    '''
    global SLEEP_GRANULARITY
    if log:
        logger.info(f'main 002 - sleep {seconds} seconds')
    else:
        logger.debug(f' sleep {seconds} seconds')
    remain = seconds
    while remain and not is_end():
        t = min(remain, SLEEP_GRANULARITY)
        logger.info(f'main 003 - remain: {remain}, SLEEP_GRAUNLARITY: {SLEEP_GRANULARITY}, t : {t}')
        time.sleep(t)
        remain -= t


def save_tar():
    '''
    tar fuzzer output and eval directories to save disk space
    '''
    global OUTPUT, TARGET, IS_DEBUG, LOG_DATETIME
    if IS_DEBUG:
        return
    # for fuzzer output
    fuzzer_files_path = os.path.join(OUTPUT, TARGET)
    tar_path = os.path.join(OUTPUT, f'{TARGET}.tar.gz')
    if os.path.exists(fuzzer_files_path) and os.path.isdir(fuzzer_files_path):
        cmd = f'tar caf {tar_path} -C {OUTPUT} {TARGET} --remove-files'
        logger.info(f'main 004 - {cmd}')
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL)
    # for eval directories
    fuzzer_files_path = os.path.join(OUTPUT, 'eval')
    tar_path = os.path.join(OUTPUT, f'{TARGET}_{LOG_DATETIME}.tar.gz')
    if os.path.exists(fuzzer_files_path) and os.path.isdir(fuzzer_files_path):
        cmd = f'tar caf {tar_path} -C {OUTPUT} eval --remove-files'
        logger.info(f'main 005 - {cmd}')
        subprocess.run(cmd, shell=True, stdout=subprocess.DEVNULL)


def cleanup(exit_code=0):
    global ARGS
    logger.info('main 006 - cleanup')
    LOG['end_time'] = time.time()
    write_log()
    for fuzzer in FUZZERS:
        stop(fuzzer)
    if exit_code == 0 and ARGS.tar:
        save_tar()
    os._exit(exit_code)


def cleanup_exception(etype, value, tb):
    traceback.print_exception(etype, value, tb)
    cleanup(1)


def init():
    global START_TIME, LOG
    signal.signal(signal.SIGTERM, lambda x, frame: sys.exit(0))
    signal.signal(signal.SIGINT, lambda x, frame: sys.exit(0))
    atexit.register(cleanup)
    sys.excepthook = cleanup_exception
    health_check_path = os.path.realpath(os.path.join(ARGS.output, 'health'))
    pathlib.Path(health_check_path).touch(mode=0o666, exist_ok=True)
    LOG['log'] = []
    LOG['round'] = []


def json_dumper(obj):
    if isinstance(obj, Path):
        return str(obj.resolve())
    try:
        return obj.toJSON()
    except:
        pass
    try:
        return obj.__dict__
    except:
        pass
    try:
        return obj.__repr__
    except:
        pass
    assert False, 'json dumper error'


def append_log(key, val, do_copy=True):
    global LOG
    if do_copy:
        val = copy.deepcopy(val)
    LOG[key].append(val)


def write_log():
    global LOG, RUNNING
    if not RUNNING:
        logger.info('main 007 - Not RUNNING, No log')
        return
    if OUTPUT and LOG_FILE_NAME:
        with open(f'{OUTPUT}/{LOG_FILE_NAME}', 'w') as f:
            f.write(json.dumps(LOG, default=json_dumper))
    else:
        assert False, 'update_log error'


def thread_write_log():
    '''
    periodically save log
    '''
    while not is_end_global():
        write_log()
        time.sleep(60)


def gen_fuzzer_driver_args(fuzzer: Fuzzer,
                           jobs=1,
                           input_dir=None,
                           empty_seed=False) -> dict:
    global ARGS, CGROUP_ROOT
    fuzzer_config = config['fuzzer'][fuzzer]
    target_config = config['target'][TARGET]
    seed = None
    if input_dir:
        seed = input_dir
    elif empty_seed:
        seed = '/seeds/custom/empty'
    else:
        seed = target_config['seed']
    group = target_config['group']
    target_args = target_config['args'].get(fuzzer,
                                            target_config['args']['default'])
    root_dir = os.path.realpath(ARGS.output)
    output = os.path.join(root_dir, TARGET, fuzzer)
    cgroup_path = os.path.join(CGROUP_ROOT, fuzzer)
    kw = {
        'fuzzer': fuzzer,
        'seed': seed,
        'output': output,
        'group': group,
        'program': TARGET,
        'argument': target_args,
        'thread': jobs,
        'cgroup_path': cgroup_path
    }
    return kw


def start(fuzzer: Fuzzer,
          output_dir,
          timeout,
          jobs=1,
          input_dir=None,
          empty_seed=False):
    '''
    call Fuzzer API to start fuzzer
    '''

    global JOBS, FUZZERS, ARGS
    fuzzer_config = config['fuzzer'][fuzzer]
    create_output_dir = fuzzer_config.get('create_output_dir', True)

    # NOTE: some fuzzers like angora will check whether outptu directory
    #       is non-exsitent and reports error otherwise.
    if create_output_dir:
        host_output_dir = f'{output_dir}/{ARGS.target}/{fuzzer}'
        os.makedirs(host_output_dir, exist_ok=True)
    else:
        host_output_dir = f'{output_dir}/{ARGS.target}'
        if os.path.exists(f'{output_dir}/{ARGS.target}/{fuzzer}'):
            logger.error(f'Please remove {output_dir}/{ARGS.target}/{fuzzer}')
            terminate_autofz()
        os.makedirs(host_output_dir, exist_ok=True)

    kw = gen_fuzzer_driver_args(fuzzer=fuzzer,
                                jobs=jobs,
                                input_dir=input_dir,
                                empty_seed=empty_seed)
    kw['command'] = 'start'

    fuzzer_driver.main(**kw)
    scale(fuzzer=fuzzer,
          scale_num=jobs,
          jobs=jobs,
          input_dir=input_dir,
          empty_seed=empty_seed)


def stop(fuzzer, jobs=1, input_dir=None, empty_seed=False):
    '''
    call Fuzzer API to stop fuzzer
    '''
    logger.debug(f'stop: {fuzzer}')
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer,
                                jobs=jobs,
                                input_dir=input_dir,
                                empty_seed=empty_seed)
    kw['command'] = 'stop'
    fuzzer_driver.main(**kw)


def scale(fuzzer, scale_num, jobs=1, input_dir=None, empty_seed=False):
    '''
    call Fuzzer API to scale fuzzer
    must be combined with cpu limit
    '''
    logger.debug(f'scale: {fuzzer} with scale_num {scale_num}')
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer,
                                jobs=jobs,
                                input_dir=input_dir,
                                empty_seed=empty_seed)
    kw['command'] = 'scale'
    kw['scale_num'] = scale_num
    fuzzer_driver.main(**kw)


def pause(fuzzer, jobs=1, input_dir=None, empty_seed=False):
    '''
    call Fuzzer API to pause fuzzer
    '''
    logger.debug(f'pause: {fuzzer}')
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer,
                                jobs=jobs,
                                input_dir=input_dir,
                                empty_seed=empty_seed)
    kw['command'] = 'pause'
    fuzzer_driver.main(**kw)


def resume(fuzzer, jobs=1, input_dir=None, empty_seed=False):
    '''
    call Fuzzer API to resume fuzzer
    '''
    logger.debug(f'resume: {fuzzer}')
    kw = gen_fuzzer_driver_args(fuzzer=fuzzer,
                                jobs=jobs,
                                input_dir=input_dir,
                                empty_seed=empty_seed)
    kw['command'] = 'resume'
    fuzzer_driver.main(**kw)


def do_sync(fuzzers: Fuzzers, host_root_dir: Path) -> bool:
    logger.debug('do sync once')
    fuzzer_info = maybe_get_fuzzer_info(fuzzers)
    if not fuzzer_info:
        return False
    start_time = time.time()
    sync.sync2(TARGET, fuzzers, host_root_dir)
    end_time = time.time()
    diff = end_time - start_time
    if IS_PROFILE: logger.info(f'main 008 - sync take {diff} seconds')
    coverage.sync()
    return True


def update_fuzzer_log(fuzzers):
    global LOG
    new_log_entry = maybe_get_fuzzer_info(fuzzers)
    if not new_log_entry: return
    new_log_entry = compress_fuzzer_info(fuzzers, new_log_entry)
    
    new_log_entry['timestamp'] = time.time()
    # NOTE: don't copy twice
    append_log('log', new_log_entry, do_copy=False)


def thread_update_fuzzer_log(fuzzers):
    update_time = min(60, PREP_TIME, SYNC_TIME, FOCUS_TIME)
    while not is_end():
        update_fuzzer_log(fuzzers)
        time.sleep(update_time)


def maybe_get_fuzzer_info(fuzzers) -> Optional[Coverage]:
    logger.debug('get_fuzzer_info called')

    new_fuzzer_info = nested_dict()
    for fuzzer in fuzzers:
        result = coverage.thread_run_fuzzer(TARGET,
                                            fuzzer,
                                            FUZZERS,
                                            OUTPUT,
                                            ARGS.timeout,
                                            '10s',
                                            empty_seed=ARGS.empty_seed,
                                            crash_mode=ARGS.crash_mode)
        if result is None:
            logger.debug(f'get_fuzzer_info: {fuzzer}\'s cov is None')
            return None
        cov = result['coverage']
        unique_bugs = result['unique_bugs']
        bitmap = result['bitmap']
        new_fuzzer_info['coverage'][fuzzer] = cov
        new_fuzzer_info['unique_bugs'][fuzzer] = unique_bugs
        new_fuzzer_info['bitmap'][fuzzer] = bitmap
        line_coverage = cov['line_coverage']
        line = cov['line']
        logger.debug(
            f'{fuzzer} has line_coverge {line_coverage} line {line}, bugs {unique_bugs}'
        )

    global_result = coverage.thread_run_global(TARGET,
                                               FUZZERS,
                                               OUTPUT,
                                               ARGS.timeout,
                                               '10s',
                                               empty_seed=ARGS.empty_seed,
                                               crash_mode=ARGS.crash_mode)
    if global_result is None: return None
    cov = global_result['coverage']
    unique_bugs = global_result['unique_bugs']
    bitmap = global_result['bitmap']
    new_fuzzer_info['global_coverage'] = cov
    new_fuzzer_info['global_unique_bugs'] = unique_bugs
    new_fuzzer_info['global_bitmap'] = bitmap
    logger.debug(f'global has line_coverge {cov["line"]}, bugs {unique_bugs}')

    return new_fuzzer_info


def get_fuzzer_info(fuzzers) -> Coverage:
    logger.debug('get_fuzzer_info called')

    new_fuzzer_info = nested_dict()
    for fuzzer in fuzzers:
        result = coverage.thread_run_fuzzer(TARGET,
                                            fuzzer,
                                            FUZZERS,
                                            OUTPUT,
                                            ARGS.timeout,
                                            '10s',
                                            empty_seed=ARGS.empty_seed,
                                            crash_mode=ARGS.crash_mode)
        assert result
        cov = result['coverage']
        unique_bugs = result['unique_bugs']
        bitmap = result['bitmap']
        new_fuzzer_info['coverage'][fuzzer] = cov
        new_fuzzer_info['unique_bugs'][fuzzer] = unique_bugs
        new_fuzzer_info['bitmap'][fuzzer] = bitmap
        line_coverage = cov['line_coverage']
        line = cov['line']
        logger.debug(
            f'{fuzzer} has line_coverge {line_coverage} line {line}, bugs {unique_bugs}'
        )

    global_result = coverage.thread_run_global(TARGET,
                                               FUZZERS,
                                               OUTPUT,
                                               ARGS.timeout,
                                               '10s',
                                               empty_seed=ARGS.empty_seed,
                                               crash_mode=ARGS.crash_mode)
    assert global_result
    cov = global_result['coverage']
    unique_bugs = global_result['unique_bugs']
    bitmap = global_result['bitmap']
    new_fuzzer_info['global_coverage'] = cov
    new_fuzzer_info['global_unique_bugs'] = unique_bugs
    new_fuzzer_info['global_bitmap'] = bitmap
    logger.debug(f'global has line_coverge {cov["line"]}, bugs {unique_bugs}')

    return new_fuzzer_info


def empty_fuzzer_info(fuzzers):
    new_fuzzer_info = nested_dict()
    for fuzzer in fuzzers:
        new_fuzzer_info['coverage'][fuzzer] = {'line': 0}
        new_fuzzer_info['unique_bugs'][fuzzer] = {
            "unique_bugs": 0,
            "unique_bugs_ip": 0,
            "unique_bugs_trace": 0,
            "unique_bugs_trace3": 0
        }
        new_fuzzer_info['bitmap'][fuzzer] = Bitmap.empty()

    new_fuzzer_info['global_coverage'] = {'line': 0}
    new_fuzzer_info['global_unique_bugs'] = {
        "unique_bugs": 0,
        "unique_bugs_ip": 0,
        "unique_bugs_trace": 0,
        "unique_bugs_trace3": 0
    }
    new_fuzzer_info['global_bitmap'] = Bitmap.empty()
    return new_fuzzer_info


def compress_fuzzer_info(fuzzers, fuzzer_info):
    '''
    compress bitmap to only log bitmap count
    used to save memory
    '''
    global_bitmap = fuzzer_info['global_bitmap']

    for fuzzer in fuzzers:
        bitmap = fuzzer_info['bitmap'][fuzzer]
        if not isinstance(bitmap, int):
            count = bitmap.count()
            del fuzzer_info['bitmap'][fuzzer]
            fuzzer_info['bitmap'][fuzzer] = count
            del bitmap

    if not isinstance(global_bitmap, int):
        global_count = global_bitmap.count()
        del fuzzer_info['global_bitmap']
        fuzzer_info['global_bitmap'] = global_count
        del global_bitmap

    return fuzzer_info


def set_fuzzer_cgroup(fuzzer, new_cpu):
    global CGROUPR_ROOT
    p = os.path.join('/cpu', CGROUP_ROOT[1:], fuzzer)
    t = trees.Tree()
    fuzzer_cpu_node = t.get_node_by_path(p)
    cfs_period_us = fuzzer_cpu_node.controller.cfs_period_us
    quota = int(cfs_period_us * new_cpu)
    # NOTE: minimal possible number for cgroup
    if quota < 1000:
        quota = 1000
    logger.debug(f'set fuzzer cgroup {fuzzer} {new_cpu} {quota}')
    fuzzer_cpu_node.controller.cfs_quota_us = quota


def update_fuzzer_limit(fuzzer, new_cpu):
    global ARGS, CPU_ASSIGN, INPUT
    if fuzzer not in CPU_ASSIGN: return
    if math.isclose(CPU_ASSIGN[fuzzer], new_cpu):
        return
    is_pause = math.isclose(0, new_cpu)
    if is_pause:
        # print('update pause')
        pause(fuzzer=fuzzer,
              jobs=JOBS,
              input_dir=INPUT,
              empty_seed=ARGS.empty_seed)

    # previous 0
    if math.isclose(CPU_ASSIGN[fuzzer], 0) and new_cpu != 0:
        resume(fuzzer=fuzzer,
               jobs=JOBS,
               input_dir=ARGS.input,
               empty_seed=ARGS.empty_seed)  # can be replaced by scale
    CPU_ASSIGN[fuzzer] = new_cpu

    # setup cgroup
    if not is_pause:
        set_fuzzer_cgroup(fuzzer, new_cpu)
    else:
        # give 1%
        set_fuzzer_cgroup(fuzzer, 0.01)
    scale_num = int(math.ceil(new_cpu))
    scale(fuzzer=fuzzer,
          scale_num=scale_num,
          jobs=JOBS,
          input_dir=INPUT,
          empty_seed=ARGS.empty_seed)


def fuzzer_bitmap_diff(fuzzers, before_fuzzer_info, after_fuzzer_info):
    before_global_bitmap = before_fuzzer_info['global_bitmap']
    after_bitmap = after_fuzzer_info['bitmap']
    bitmap_diff = {}
    for fuzzer in fuzzers:
        logger.info(f'main 601 - prep bitmap diff - before_bitmap : { before_global_bitmap}, after_bitmap : { after_bitmap[fuzzer]}') 
        bitmap_diff[fuzzer] = after_bitmap[fuzzer] - before_global_bitmap
    return bitmap_diff


class SchedulingAlgorithm(metaclass=SingletonABCMeta):
    @abstractmethod
    def __init__(self, fuzzers,tsFuzzers, focus=None, one_core=False, N=1):
        pass

    @abstractmethod
    def run(self):
        pass


class Schedule_Base(SchedulingAlgorithm):
    def __init__(self,
                 fuzzers: Fuzzers,
                 tsFuzzers,
                 prep_time: int,
                 focus_time: int,
                 jobs: int = 1):
        self.fuzzers = fuzzers
        self.tsFuzzers = tsFuzzers
        self.name = 'schedule_base'

        # to support multicore
        self.jobs = jobs

        self.round_num = 1
        self.round_start_time = 0
        self.first_round = True

        self.prep_fuzzers: List[Fuzzer] = []
        self.prep_time = prep_time
        self.prep_time_base = prep_time

        self.focus_time = focus_time
        self.focus_time_base = focus_time

        self.prep_time_round = 0
        self.focus_time_round = 0

        # focus

        # enfuzz
        self.sync_time = 0

        self.cov_before_prep: Coverage
        self.cov_before_focus: Coverage

        self.bitmap_contribution: BitmapContribution = {}
        self.all_bitmap_contribution: BitmapContribution = {}  # will not reset
        self.round_bitmap_contribution: Deque[BitmapContribution] = deque()
        self.round_bitmap_intersection_contribution: Deque[
            BitmapContribution] = deque()
        self.round_bitmap_distinct_contribution: Deque[
            BitmapContribution] = deque()

        self.picked_times: Dict[Fuzzer, int]

        #
        self.diff_threshold = None
        self.diff_threshold_base = None
        self.diff_threshold_round = None

    def find_new_bitmap(self):
        cov_before = self.cov_before_focus
        global_bm_before = cov_before['global_bitmap']
        cov_now = get_fuzzer_info(self.fuzzers)
        global_bm_now = cov_now['global_bitmap']

        # TODO: threshold?
        return global_bm_now > global_bm_before

    def run_one(self, prep):
        for fuzzer in self.fuzzers:
            if fuzzer == prep:
                update_fuzzer_limit(fuzzer, JOBS)
            else:
                update_fuzzer_limit(fuzzer, 0)

    def run_one_cpu(self, prep):
        for fuzzer in self.fuzzers:
            if fuzzer == prep:
                update_fuzzer_limit(fuzzer, 1)
            else:
                update_fuzzer_limit(fuzzer, 0)

    def prep_wait(self, prep_time):
        sleep(prep_time)

    def enfuzz(self):
        global OUTPUT

        sync_time = self.sync_time
        for fuzzer in self.fuzzers:
            self.run_one(fuzzer)
            self.prep_wait(sync_time)
            do_sync(self.fuzzers, OUTPUT)

    def enfuzz_jobs(self, sync=True):
        global OUTPUT
        assert self.jobs
        sync_time = self.sync_time
        num_fuzzers = len(self.fuzzers)
        cpu_per_fuzzer = self.jobs / num_fuzzers
        for fuzzer in self.fuzzers:
            update_fuzzer_limit(fuzzer, cpu_per_fuzzer)
        self.prep_wait(sync_time)
        # sync after running
        if sync:
            do_sync(self.fuzzers, OUTPUT)

    def enfuzz_jobs_time(self, run_time, sync=True):
        global OUTPUT
        assert self.jobs
        num_fuzzers = len(self.fuzzers)
        cpu_per_fuzzer = self.jobs / num_fuzzers
        for fuzzer in self.fuzzers:
            update_fuzzer_limit(fuzzer, cpu_per_fuzzer)
        self.prep_wait(run_time)
        # sync after running
        if sync:
            do_sync(self.fuzzers, OUTPUT)

    def has_winner(self) -> bool:
        assert self.diff_threshold is not None

        ret = False
        current_fuzzer_info = get_fuzzer_info(self.fuzzers)
        global_bitmap = current_fuzzer_info['global_bitmap'].count()
        bitmap_diff = fuzzer_bitmap_diff(self.fuzzers,
                                         self.before_prep_fuzzer_info,
                                         current_fuzzer_info)
        minv = 2**32
        maxv = 0
        for fuzzer in self.fuzzers:
            minv = min(minv, bitmap_diff[fuzzer].count())
            maxv = max(maxv, bitmap_diff[fuzzer].count())
        diff = maxv - minv
        # NOTE: threshold to determine whether we find a large difference
        self.diff_round = diff
        if diff > self.diff_threshold:
            ret = True
        logger.debug(f'has winner: {ret}, diff: {diff}, {bitmap_diff}')
        return ret

    def prep_round_robin(self) -> bool:
        prep_time = self.prep_time
        remain_time = prep_time
        for fuzzer in FUZZERS:
            self.tsFuzzers[fuzzer].threshold = self.diff_threshold / 10

        prep_round = 1

        while remain_time > 0:
            '''
            run 60 seconds for each fuzzer and see whether there is a winner
            '''
            run_time = min(remain_time, 30)
            for prep in self.prep_fuzzers:
                self.run_one(prep)
                self.prep_wait(run_time)
            self.dynamic_prep_time_round += run_time
            remain_time -= run_time
            '''
            detect whether there is a winner
            '''
            current_fuzzer_info = get_fuzzer_info(self.fuzzers)

            if prep_round == 1:
                bitmap_diff =fuzzer_bitmap_diff(self.fuzzers, self.before_prep_fuzzer_info, current_fuzzer_info)
            else:
                bitmap_diff = fuzzer_bitmap_diff(self.fuzzers, previous_fuzzer_info, current_fuzzer_info)

            for fuzzer in self.fuzzers:
                logger.info(f'main 042 - fuzzer : {fuzzer}, fuzzer_bitmap_diff : {bitmap_diff[fuzzer].count()}')
                if bitmap_diff[fuzzer].count() > self.tsFuzzers[fuzzer].threshold:
                    thompson.updateFuzzerCountPrep(self.tsFuzzers, fuzzer, 1)
                    self.tsFuzzers[fuzzer].threshold += self.tsFuzzers[fuzzer].threshold
                else:
                    thompson.updateFuzzerCountPrep(self.tsFuzzers, fuzzer, 0)
                    self.tsFuzzers[fuzzer].threshold *= 0.5
                    

            for fuzzer in FUZZERS:
                logger.info(f'main 043 - prep_round : {prep_round} end result - fuzzer : { fuzzer }, fuzzer_success : { self.tsFuzzers[fuzzer].S }, fuzzer_fail : { self.tsFuzzers[fuzzer].F}, threshold : {self.tsFuzzers[fuzzer].threshold }')
            previous_fuzzer_info = current_fuzzer_info
            prep_round+=1

            global OUTPUT
            do_sync(self.fuzzers,OUTPUT)



#            self.has_winner_round = self.has_winner()
            # NOTE: early exit!
#            if self.has_winner_round:
#                return True
        return False

    def prep_parallel(self) -> bool:
        logger.debug('prep parallel unfixed prep')
        prep_time = self.prep_time

        for fuzzer in FUZZERS:
            num_prep = len(self.prep_fuzzers)
            if fuzzer in self.prep_fuzzers:
                update_fuzzer_limit(fuzzer, JOBS / num_prep)
            else:
                update_fuzzer_limit(fuzzer, 0)

        remain_time = prep_time
        while remain_time > 0:
            '''
            run 30 seconds for each fuzzer and see whether there is a winner
            '''
            run_time = min(remain_time, 30)
            self.prep_wait(run_time)
            self.dynamic_prep_time_round += run_time
            remain_time -= run_time
            '''
            detect whether there is a winner
            '''
            self.has_winner_round = self.has_winner()
            # NOTE: early exit!
            if self.has_winner_round:
                return True
        return False

    def focus_cpu_assign(self,  new_cpu_assign, focus_time: int) -> bool:
        '''
        return whether we find new coverage during focus phase
        '''
        global OUTPUT, JOBS
        # NOTE: a little different with origial version
        sorted_cpu_assign = [(k, v) for k, v in sorted(
            new_cpu_assign.items(), key=lambda item: item[1], reverse=True)]

        num_prep_fuzzers: int = len(self.prep_fuzzers)
        focus_total = focus_time * num_prep_fuzzers
        focus_fuzzer_cpu_time = {}

        logger.info(f'main 009 - focus_total: { focus_total}, focus_time: {focus_time}')

        run_fuzzers = []

        # sorted now!
        # better fuzzer snow can run first to help others
        for fuzzer, new_cpu in sorted_cpu_assign:
            run_fuzzers.append(fuzzer)
            focus_fuzzer_cpu_time[fuzzer] = focus_total * (new_cpu / JOBS)
            logger.info(f'main 010 - focus_fuzzer_cpu_time: {focus_fuzzer_cpu_time[fuzzer]}, fuzzer: {fuzzer}, new_cpu:{new_cpu}')

        logger.debug(f"cpu_assign: {new_cpu_assign}")
        logger.debug(f"sorted_cpu_assign: {sorted_cpu_assign}")
        logger.debug(f"focus_fuzzer_time: {focus_fuzzer_cpu_time}")

        focusFail = 0
        focusSuccess = 0

        focusBeforeInfo = get_fuzzer_info(self.fuzzers)

        previousBitmap = focusBeforeInfo['global_bitmap'].count()
        previousBug = focusBeforeInfo['global_unique_bugs']['unique_bugs']

        focusThreshold = self.diff_threshold/10

        for fuzzer in run_fuzzers:
            t = focus_fuzzer_cpu_time[fuzzer]
            logger.info(f'main 011 - focus {fuzzer} runTime :{t}')
            logger.debug(f"focus_cpu_assign: {fuzzer}, time: {t}")

            focusRemainTime = t
            logger.info(f'main 701 - focus remain time init : {focusRemainTime}')
            focusRound = 1

            while focusRemainTime > 0 :
                focusRunTime = min(focusRemainTime, 60)
                self.run_one(fuzzer)
                sleep(focusRunTime)

                self.tsFuzzers[fuzzer].total_runTime += focusRunTime
                focusRoundInfo = get_fuzzer_info(self.fuzzers)
                currentBitmap = focusRoundInfo['bitmap'][fuzzer].count()
                currentBug = focusRoundInfo['unique_bugs'][fuzzer]['unique_bugs']

                # Evaluation
                if currentBitmap - previousBitmap > self.tsFuzzers[fuzzer].threshold  or currentBug - previousBug >0:
                    thompson.updateFuzzerCount(self.tsFuzzers,run_fuzzers,1)
                    focusFail = 0
                    focusSuccess += 1
                    #focusRemainTime += t
                    self.tsFuzzers[fuzzer].threshold += focusThreshold
                else:
                    thompson.updateFuzzerCount(self.tsFuzzers,run_fuzzers,0)
                    focusFail += 1
                    #self.tsFuzzers[fuzzer].stack += 1
                    self.tsFuzzers[fuzzer].threshold *= 0.5
                focusRemainTime -= focusRunTime

                logger.info(f'main 501 - focus round : {focusRound}end result - fuzzer : {fuzzer}, previousBitmap : {previousBitmap}, currentBitmap : {currentBitmap}, previousBug : {previousBug}, currentBug : {currentBug}, focusSuccess : {focusSuccess}, focusFail : {focusFail}, fuzzer success :  {self.tsFuzzers[fuzzer].S}, fuzzer fail : {self.tsFuzzers[fuzzer].F}, focusThreshold : {self.tsFuzzers[fuzzer].threshold}, fuzzer stack : {self.tsFuzzers[fuzzer].stack}, focusRemainTime : {focusRemainTime}, focusRunTime : {focusRunTime}')
                previousBitmap = currentBitmap
                previousBug = currentBug
                focusRound += 1

                # 300s
                if focusFail == 5:
                    break
            # we can sync infinitely in focus session
            # optimization: only sync between run_fuzzers
            do_sync(run_fuzzers, OUTPUT)

        return self.find_new_bitmap()

    def focus_cpu_assign_parallel(self, new_cpu_assign,
                                  focus_time: int) -> bool:
        global OUTPUT, FUZZERS, JOBS
        logger.debug('focus parallel')
        for fuzzer, new_cpu in new_cpu_assign.items():
            update_fuzzer_limit(fuzzer, new_cpu)
        for fuzzer in FUZZERS:
            if fuzzer not in new_cpu_assign:
                update_fuzzer_limit(fuzzer, 0)
        sleep(focus_time)
        return self.find_new_bitmap()

    def focus_one(self, focus_fuzzer):
        assert focus_fuzzer in self.fuzzers
        for fuzzer in self.fuzzers:
            new_cpu = JOBS if fuzzer == focus_fuzzer else 0
            update_fuzzer_limit(fuzzer, new_cpu)
        logger.debug(f'focus one: {focus_fuzzer}')

    def get_bitmap_intersection(self, fuzzers, bitmaps):
        intersection = Bitmap.full()
        for fuzzer in fuzzers:
            bm = bitmaps[fuzzer]
            intersection &= bm
        return intersection

    def get_fuzzer_info_bitmap_intersection(self, fuzzers, fuzzer_info):
        return self.get_bitmap_intersection(fuzzers, fuzzer_info['bitmap'])

    def get_bitmap_union(self, fuzzers, bitmaps):
        union = Bitmap.empty()
        for fuzzer in fuzzers:
            bm = bitmaps[fuzzer]
            union |= bm
        return union

    def get_fuzzer_info_bitmap_union(self, fuzzers, fuzzer_info):
        return self.get_bitmap_union(fuzzers, fuzzer_info['bitmap'])

    def get_bitmap_intersection_contribution(self, fuzzers, fuzzer_info):
        intersection = self.get_fuzzer_info_bitmap_intersection(
            fuzzers, fuzzer_info)
        contribution = {}
        for fuzzer in fuzzers:
            contribution[fuzzer] = fuzzer_info['bitmap'][fuzzer] - intersection
        return contribution

    # NOTE: unused, an alternative way to calcualte contribution
    def get_bitmap_distinct_contribution(self, fuzzers, fuzzer_info):
        contribution = {}
        for fuzzer in fuzzers:
            filtered = fuzzers.copy()
            filtered.remove(fuzzer)
            union = self.get_fuzzer_info_bitmap_union(filtered, fuzzer_info)
            contribution[fuzzer] = fuzzer_info['bitmap'][fuzzer] - union
        return contribution

    def reset_bitmap_contribution(self):
        logger.debug('reset bitmap contribution')
        for fuzzer in self.fuzzers:
            self.bitmap_contribution[fuzzer] = Bitmap.empty()

    def add_bitmap_prep_contribution(self, fuzzers, before_fuzzer_info,
                                     after_fuzzer_info):
        bitmap_diff = fuzzer_bitmap_diff(fuzzers, before_fuzzer_info,
                                         after_fuzzer_info)
        for fuzzer in fuzzers:
            self.bitmap_contribution[fuzzer] += bitmap_diff[fuzzer]
            self.all_bitmap_contribution[fuzzer] += bitmap_diff[fuzzer]

    def calculate_cpu_bitmap_intersection(self, fuzzers, fuzzer_info,
                                          focus_time):
        global JOBS
        # NOTE: 1 to not elimaite any one
        cpu_threshold = 0
        # NOTE min focus_time to reduce unnecessary context switch
        focus_time_thrshold = 20
        bitmap_contribution = self.get_bitmap_intersection_contribution(
            fuzzers, fuzzer_info)
        contribution = {}
        for fuzzer in fuzzers:
            contribution[fuzzer] = bitmap_contribution[fuzzer].count()
        logger.debug(f'contribution {contribution}')
        # check all zero or not
        summation = sum(contribution.values())
        picked = []
        cpu_assign = {}
        fuzzer_num = len(fuzzers)

        if summation == 0:
            for fuzzer in fuzzers:
                cpu_assign[fuzzer] = JOBS / fuzzer_num
                picked.append(fuzzer)
            return picked, cpu_assign

        summation2 = 0
        reduced = []

        # ignore fuzzer cpu < threshold
        for fuzzer in fuzzers:
            cpu_ratio = contribution[fuzzer] / summation
            cpu = JOBS * cpu_ratio
            if cpu >= cpu_threshold and (cpu * focus_time *
                                         len(fuzzers)) > focus_time_thrshold:
                summation2 += contribution[fuzzer]
                reduced.append(fuzzer)

        for fuzzer in reduced:
            cpu_ratio = contribution[fuzzer] / summation2
            cpu = JOBS * cpu_ratio
            cpu_assign[fuzzer] = cpu
            picked.append(fuzzer)

        return picked, cpu_assign

    def picked_rate(self, fuzzer):
        if self.round_num == 1: return 1
        return self.picked_times[fuzzer] / (self.round_num - 1)

    def pre_round(self):
        pass

    def one_round(self):
        pass

    def post_round(self):
        pass

    def main(self):
        # main while loop
        while True:
            if is_end(): return
            if not self.pre_round(): continue
            logger.info(f'main 012 - round {self.round_num} start')
            self.one_round()
            logger.info(f'main 013 - round {self.round_num} end')
            self.post_round()

    def pre_run(self) -> bool:
        logger.info(f"main 014 - {self.name}: pre_run")
        return True

    def run(self):
        if not self.pre_run():
            return
        self.main()
        self.post_run()

    def post_run(self):
        logger.info(f"main 015 - {self.name}: post_run")


class Schedule_EnFuzz(Schedule_Base):
    '''
    EnFuzz/CUPID/autofz-
    '''
    def __init__(self, fuzzers, sync_time, jobs):
        # no use parent's init
        self.fuzzers = fuzzers
        self.sync_time = sync_time
        self.name = f'EnFuzz_{sync_time}_j{jobs}'
        self.jobs = jobs

    def pre_round(self):

        update_success = maybe_get_fuzzer_info(fuzzers=self.fuzzers)
        if not update_success:
            SLEEP = 10
            logger.info(
                f'main 016 - wait for all fuzzer having coverage, sleep {SLEEP} seconds')
            sleep(SLEEP)
            global START_TIME
            elasp = time.time() - START_TIME
            if elasp > 600:
                terminate_autofz()
        return update_success

    def one_round(self):
        if self.jobs == 1:
            # round-robin version if jobs == 1
            self.enfuzz()
        else:
            self.enfuzz_jobs()

    def post_round(self):
        fuzzer_info = get_fuzzer_info(self.fuzzers)
        fuzzer_info = compress_fuzzer_info(self.fuzzers, fuzzer_info)
        append_log('round', {'fuzzer_info': fuzzer_info})

    def main(self):
        while True:
            if is_end(): return
            if not self.pre_round(): continue
            self.one_round()
            self.post_round()

    def pre_run(self) -> bool:
        logger.info(f"main 017 - {self.name}: pre_run")
        return True

    def run(self):
        if not self.pre_run():
            return
        self.main()
        self.post_run()

    def post_run(self):
        logger.info(f"main 018 - {self.name}: post_run")


class Schedule_Focus(Schedule_Base):
    def __init__(self, fuzzers, focus):
        self.fuzzers = fuzzers
        self.focus = focus
        self.name = f'Focus_{focus}'

    def pre_round(self):

        update_success = maybe_get_fuzzer_info(fuzzers=self.fuzzers)
        if not update_success:
            SLEEP = 10
            logger.info(
                f'main 019 - wait for all fuzzer having coverage, sleep {SLEEP} seconds')
            sleep(SLEEP)
            global START_TIME
            elasp = time.time() - START_TIME
            if elasp > 600:
                terminate_autofz()
        return update_success

    def one_round(self):
        self.focus_one(self.focus)
        sleep(300)

    def post_round(self):
        fuzzer_info = get_fuzzer_info(self.fuzzers)
        fuzzer_info = compress_fuzzer_info(self.fuzzers, fuzzer_info)
        append_log('round', {'fuzzer_info': fuzzer_info})

    def main(self):
        while True:
            if is_end(): return
            if not self.pre_round(): continue
            self.one_round()
            self.post_round()

    def pre_run(self) -> bool:
        logger.info(f"main 020 - {self.name}: pre_run")
        return True

    def run(self):
        if not self.pre_run():
            return
        self.main()
        self.post_run()

    def post_run(self):
        logger.info(f"main 021 - {self.name}: post_run")


class Schedule_Autofz(Schedule_Base):
    '''
    combination of best-only and resource distribution
    based on whether we can find a winning fuzzer in prep phase
    unfixed prep time: terminate prepation phase earlier if
    we already see the difference among fuzzer performance
    '''
    def __init__(self,
                 fuzzers,tsFuzzers,
                 prep_time=300,
                 focus_time=300,
                 diff_threshold=10):
        '''
        prep_time: total time for prep phase + focus phase
        diff_threshold: bitmap diff to determine whether there is a clear winner
        if we find a winner in the prep phase, we use the remaining time for focus phase
        '''
        # focus time is dynamically determined
        super().__init__(fuzzers=fuzzers,tsFuzzers=tsFuzzers,
                         prep_time=prep_time,
                         focus_time=focus_time)
        self.name = f'Autofz_{prep_time}_{focus_time}_AIMD_DT{diff_threshold}'
        self.policy_bitmap = policy.BitmapPolicy()
        self.focused_round = []
        self.picked_times = {}
        self.before_prep_fuzzer_info = empty_fuzzer_info(self.fuzzers)
        self.find_new_round = False

        self.diff_threshold = diff_threshold
        self.diff_threshold_base = diff_threshold
        self.diff_threshold_round = diff_threshold

        self.diff_round = 0
        self.has_winner_round = False

        self.dynamic_prep_time_round = 0
        self.dynamic_focus_time_round = 0

    # prepare round setting - sync + init variable
    def pre_round(self):
        self.round_start_time = time.time()
        update_success = maybe_get_fuzzer_info(fuzzers=self.fuzzers)
        

        if not update_success:
            SLEEP = 10
            logger.info(
                f'main 022 - wait for all fuzzer having coverage, sleep {SLEEP} seconds')
            sleep(SLEEP)
            global START_TIME
            elasp = time.time() - START_TIME
            if elasp > 600:
                terminate_autofz()

        self.prep_time_round = 0
        self.focus_time_round = 0
        self.dynamic_prep_time_round = 0
        self.dynamic_focus_time_round = 0
        self.focused_round = []
        self.has_winner_round = False

        return update_success

    def one_round(self):
        round_start_time = time.time()
        self.diff_threshold_round = self.diff_threshold

        global OUTPUT
        do_sync(self.fuzzers, OUTPUT)
        if self.first_round:
            fuzzer_info = empty_fuzzer_info(self.fuzzers)
        else:
            fuzzer_info = get_fuzzer_info(self.fuzzers)

        self.before_prep_fuzzer_info = fuzzer_info
        logger.debug(f'before_fuzzer_info: {self.before_prep_fuzzer_info}')

        prep_fuzzers = self.fuzzers
        self.prep_fuzzers = prep_fuzzers

        logger.info(f'main 023 - round {self.round_num} preparation phase')
        previous_bitmap = fuzzer_info['global_bitmap'].count()
        previous_unique_bug = fuzzer_info['global_unique_bugs']['unique_bugs']

        logger.info(f'main 041 - previous unique bug : {previous_unique_bug}')

        # preparation phase - 3 step
        # check early exit condition
        if self.round_num == 1:
            if PARALLEL:
                has_winner = self.prep_parallel()
            else:
                has_winner = self.prep_round_robin()
            
            fuzzer_threshold_sum =0
            for fuzzer in FUZZERS:
                fuzzer_threshold_sum += self.tsFuzzers[fuzzer].threshold
                logger.info(f'main 044 - preparation  end result - fuzzer : { fuzzer }, fuzzer_success : { self.tsFuzzers[fuzzer].S }, fuzzer_fail : { self.tsFuzzers[fuzzer].F }, fuzzer run time_prep : {self.prep_time}, fuzzer threshold : {self.tsFuzzers[fuzzer].threshold}')
            fuzzer_threshold_av = int(fuzzer_threshold_sum/len(FUZZERS))
            logger.info(f'main 200 - fuzzer_threshold_av : {fuzzer_threshold_av}')
            self.diff_threshold = fuzzer_threshold_av

        
        selected_fuzzers = thompson.selectFuzzer(self.tsFuzzers)
        logger.info(f'main 024 - selected_fuzzers: {selected_fuzzers}')


        prep_end_time = time.time()
        fuzzer_info = get_fuzzer_info(self.fuzzers)
        after_prep_fuzzer_info = fuzzer_info
        
        if self.round_num == 1 :
            preparation_bitmap = after_prep_fuzzer_info['global_bitmap'].count()
            preparation_unique_bug = after_prep_fuzzer_info['global_unique_bugs']['unique_bugs']
            logger.info(f'main 045 - preparation_bitmap: {preparation_bitmap}, preparation_unique_bug : {preparation_unique_bug}')

        logger.debug(f'after_fuzzer_info: {after_prep_fuzzer_info}')

        # no means
        #bitmap_diff = fuzzer_bitmap_diff(self.fuzzers,  self.before_prep_fuzzer_info, after_prep_fuzzer_info)
        # no means
        #self.add_bitmap_prep_contribution(prep_fuzzers, self.before_prep_fuzzer_info, after_prep_fuzzer_info)

        #logger.debug(f'BITMAP_DIFF: {bitmap_diff}')
        #logger.debug(f'BITMAP_PREP_CONTRIBUTION: {self.bitmap_contribution}')

        # NOTE: after bitmap contribution

        picked_fuzzers, cpu_assign = [], {}
        picked_fuzzers, cpu_assign = self.policy_bitmap.calculate_cpu(selected_fuzzers,after_prep_fuzzer_info, JOBS)


        # no means
        # NOTE: has winner => delta > threshold
        #if has_winner:
            # best only
        #     picked_fuzzers, cpu_assign = self.policy_bitmap.calculate_cpu(
        #         prep_fuzzers, after_prep_fuzzer_info, JOBS)

            # AIMD threshold additive part
        #     self.diff_threshold += self.diff_threshold_base
        # else:
            # resource distibution
        #     picked_fuzzers, cpu_assign = self.calculate_cpu_bitmap_intersection(
        #         prep_fuzzers, after_prep_fuzzer_info, self.focus_time)

            # AIMD threshold multiplicative part (div 2)
        #     self.diff_threshold *= 0.5

        # until here

        # check pick before fuzzer picked_time
        for fuzzer in self.fuzzers:
             logger.info(f'main 025 - pick before fuzzer: {fuzzer}, picked_time : {self.picked_times[fuzzer]}')


        # check picked_fuzzer
        for fuzzer in picked_fuzzers:
            self.picked_times[fuzzer] += 1
        
        # check pick after fuzzer picked_time
        for fuzzer in self.fuzzers:
            logger.info(f'main 026 - pick after fuzzer: {fuzzer}, picked_time : {self.picked_times[fuzzer]}')

        # focus session
        self.cov_before_focus = after_prep_fuzzer_info

        # no means
        # do_sync(self.fuzzers, OUTPUT)

        # reset focus time
        self.dynamic_focus_time_round = self.focus_time

        logger.info(f'main 027 - prep_time : {self.prep_time}, dynamic_prep_time_round: {self.dynamic_prep_time_round}, focus_time: {self.focus_time}, dynamic_focus_time_round: {self.dynamic_focus_time_round}')



        # focus time fix 
        #if has_winner:
        #    self.dynamic_focus_time_round = self.prep_time - self.dynamic_prep_time_round + self.focus_time
        #else:
        #    self.dynamic_focus_time_round = self.focus_time

        logger.debug(
            f'prep time: {self.dynamic_prep_time_round}, focus time: {self.dynamic_focus_time_round}'
        )

        find_new = False
        focus_start_time = time.time()

        logger.info(f'main 028 - round {self.round_num} focus phase')

        # run focus fuzzer
        find_new = self.focus_cpu_assign(cpu_assign, self.dynamic_focus_time_round)

        # NOTE: focus phase
        #if PARALLEL:
        #    find_new = self.focus_cpu_assign_parallel(
        #        cpu_assign, self.dynamic_focus_time_round)
        #else:
        #    logger.debug('scheduling focus session')
        #    find_new = self.focus_cpu_assign(cpu_assign,
        #                                     self.dynamic_focus_time_round)
        
        # logger.info(f'find_new: {find_new}')

        logger.debug(f'find new is {find_new}')
        focus_end_time = time.time()

        # no means
        #focus_elasp = focus_end_time - focus_start_time
        #logger.debug(f'focus elasp: {focus_elasp} seconds')

        self.find_new_round = find_new

        after_focus_fuzzer_info = get_fuzzer_info(self.fuzzers)
        logger.debug(f'focused_round: {self.focused_round}')

        current_bitmap = after_focus_fuzzer_info['global_bitmap'].count()
        current_unique_bug = after_focus_fuzzer_info['global_unique_bugs']['unique_bugs']
        # logger.info(f"after_info : {after_focus_fuzzer_info['bitmap']}")

        # update fuzzer count criteria
        if self.round_num == 1 :
            logger.info(f'main 029 - round {self.round_num} end - preparation_bitmap: {preparation_bitmap}, current_bitmap: {current_bitmap}, preparation_unique_bug : { preparation_unique_bug}, current_unique_bug : { current_unique_bug},  diff_threshold: {self.diff_threshold}')
        else:
            logger.info(f'main 029 - round {self.round_num} end - previous_bitmap: {previous_bitmap}, current_bitmap: {current_bitmap}, previous_unique_bug : { previous_unique_bug}, current_unique_bug : {current_unique_bug}, diff_threshold: {self.diff_threshold}')

#        if self.round_num == 1:
#            if current_bitmap - preparation_bitmap > self.diff_threshold or current_unique_bug - preparation_unique_bug > 0:
#                #thompson.updateFuzzerCount(self.tsFuzzers, selected_fuzzers, 1)
#                self.diff_threshold += self.diff_threshold_base
#            else:
#                #thompson.updateFuzzerCount(self.tsFuzzers, selected_fuzzers, 0)
#                self.diff_threshold *= 0.5
#        else:
#            if current_bitmap - previous_bitmap > self.diff_threshold or current_unique_bug - previous_unique_bug > 0:
#                #thompson.updateFuzzerCount(self.tsFuzzers, selected_fuzzers, 1)
#                self.diff_threshold += self.diff_threshold_base
#            else:
#                #thompson.updateFuzzerCount(self.tsFuzzers, selected_fuzzers, 0)
#                self.diff_threshold *= 0.5

        bug_info = after_focus_fuzzer_info['global_unique_bugs']
        logger.info(f'main 030 - round {self.round_num} end result - bug : {bug_info}')

        for fuzzer in FUZZERS:
            #self.tsFuzzers[fuzzer].stack += 1
            logger.info(f'main 031 - round {self.round_num} end result - fuzzer : { fuzzer }, fuzzer_success : { self.tsFuzzers[fuzzer].S }, fuzzer_fail : { self.tsFuzzers[fuzzer].F }, fuzzer run time : {self.tsFuzzers[fuzzer].total_runTime}, fuzzer stack : {self.tsFuzzers[fuzzer].stack}, fuzzer threshold : {self.tsFuzzers[fuzzer].threshold}')

        #assert (self.dynamic_prep_time_round + self.dynamic_focus_time_round) == (self.prep_time + self.focus_time)
        
        append_log(
            'round', {
                'round_num':
                self.round_num,
                'start_time':
                round_start_time,
                'prep_end_time':
                prep_end_time,
                'focus_start_time':
                focus_start_time,
                'focus_end_time':
                focus_end_time,
                'end_time':
                time.time(),
                'prep_time':
                self.prep_time_round,
                'focus_time':
                self.focus_time_round,
                'dynamic_prep_time':
                self.dynamic_prep_time_round,
                'dynamic_focus_time':
                self.dynamic_focus_time_round,
                'first_round':
                self.first_round,
                'before_prep_fuzzer_info':
                compress_fuzzer_info(self.fuzzers,
                                     self.before_prep_fuzzer_info),
                'before_focus_fuzzer_info':
                compress_fuzzer_info(self.fuzzers, after_prep_fuzzer_info),
                'after_focus_fuzzer_info':
                compress_fuzzer_info(self.fuzzers, after_focus_fuzzer_info),
                'picked_fuzzers':
                picked_fuzzers,
                'prep_fuzzers':
                prep_fuzzers,
                'picked_times':
                self.picked_times,
                'cpu_assign':
                cpu_assign,
                'has_winner':
                self.has_winner_round,
                'diff':
                self.diff_round,
                'diff_threshold':
                self.diff_threshold_round
            })

    def post_round(self):
        now = time.time()
        elasp = now - self.round_start_time
        logger.debug(f'round elasp: {elasp} seconds')
        self.first_round = False

        self.round_num += 1

    def pre_run(self) -> bool:
        logger.info(f"main 032 - {self.name}: pre_run")
        logger.info(f'main 033 - diff_threshold {self.diff_threshold}')
        self.reset_bitmap_contribution()
        for fuzzer in self.fuzzers:
            self.all_bitmap_contribution[fuzzer] = Bitmap.empty()
            self.picked_times[fuzzer] = 0
        return True


def init_cgroup():
    '''
    cgroup /autofz is created by /init.sh, the command is the following:

    cgcreate -t yufu -a yufu -g cpu:/autofz
    '''
    global FUZZERS, CGROUP_ROOT
    # start with /
    cgroup_path = cgroup_utils.get_cgroup_path()
    container_id = os.path.basename(cgroup_path)
    cgroup_path_fs = os.path.join('/sys/fs/cgroup/cpu', cgroup_path[1:])
    autofz_cgroup_path_fs = os.path.join(cgroup_path_fs, 'autofz')
    # print(autofz_cgroup_path_fs)
    if not os.path.exists(autofz_cgroup_path_fs):
        logger.critical(
            'autofz cgroup not exists. make sure to run /init.sh first')
        terminate_autofz()
    t = trees.Tree()
    p = os.path.join('/cpu', cgroup_path[1:], 'autofz')
    CGROUP_ROOT = os.path.join(cgroup_path, 'autofz')
    # print('CGROUP_ROOT', CGROUP_ROOT)
    cpu_node = t.get_node_by_path(p)
    for fuzzer in FUZZERS:
        fuzzer_cpu_node = t.get_node_by_path(os.path.join(p, fuzzer))
        if not fuzzer_cpu_node:
            fuzzer_cpu_node = cpu_node.create_cgroup(fuzzer)
        cfs_period_us = fuzzer_cpu_node.controller.cfs_period_us
        # default to JOBS / num_of_fuzzers
        # defaut to full
        quota = int(cfs_period_us * (JOBS))
        # print(fuzzer_cpu_node, quota)
        fuzzer_cpu_node.controller.cfs_quota_us = quota
    return True


def main():
    global LOG, ARGS, TARGET, FUZZERS, TARGET, SYNC_TIME, PREP_TIME
    global FOCUS_TIME, JOBS, OUTPUT, INPUT, LOG_DATETIME, LOG_FILE_NAME
    global CPU_ASSIGN
    global START_TIME
    global RUNNING
    global PARALLEL
    random.seed()
    ARGS = cli.ArgsParser().parse_args()

    logger.info(f'main 034 - ARGS(user set option) : {ARGS}')

    TARGET = ARGS.target
    unsuppored_fuzzers = config['target'][TARGET].get('unsupported', [])
    logger.debug(f'autofz args is {ARGS}')
    available_fuzzers = list(config['fuzzer'].keys())
    available_fuzzers = [
        fuzzer for fuzzer in available_fuzzers
        if fuzzer not in unsuppored_fuzzers
    ]
    FUZZERS = available_fuzzers if 'all' in ARGS.fuzzer else ARGS.fuzzer
    logger.debug(f'FUZZERS: {FUZZERS}')

    # make things easier
    if ARGS.focus_one:
        FUZZERS = [ARGS.focus_one]
    OUTPUT = ARGS.output.resolve()
    if ARGS.input:
        INPUT = ARGS.input.resolve()
    else:
        INPUT = None
    for fuzzer in FUZZERS:
        if ARGS.focus_one and fuzzer != ARGS.focus_one: continue
        if not fuzzing.check(TARGET, fuzzer, OUTPUT):
            exit(1)
    try:
        os.makedirs(OUTPUT, exist_ok=False)
    except FileExistsError:
        logger.error(f'remove {OUTPUT}')
        exit(1)

    with open(os.path.join(OUTPUT, 'cmdline'), 'w') as f:
        cmdline = " ".join(sys.argv)
        LOG['cmd'] = cmdline
        f.write(f"{cmdline}\n")
    init()
    current_time = time.time()
    LOG['autofz_args'] = ARGS.as_dict()  # remove Namespace
    LOG['autofz_config'] = config
    LOG['start_time'] = current_time
    LOG['algorithm'] = None

    SYNC_TIME = ARGS.sync
    PREP_TIME = ARGS.prep
    FOCUS_TIME = ARGS.focus

    # NOTE: default is 1 core
    JOBS = ARGS.jobs
    timeout = ARGS.timeout
    PARALLEL = ARGS.parallel

    result = coverage.thread_run_global(TARGET,
                               FUZZERS,
                               OUTPUT,
                               ARGS.timeout,
                               '10s',
                               input_dir=INPUT,
                               empty_seed=ARGS.empty_seed,
                               crash_mode=ARGS.crash_mode,
                               input_only=False)

    # wait for seed evaluated
    START_TIME = time.time()

    # setup cgroup
    init_cgroup()

    # create thompson sampling fuzzer variable
    tsFuzzers = {}

    # init fuzzer - success count and fail count
    for fuzzer in FUZZERS:
        tsFuzzers[fuzzer] = thompson.fuzzer()
        logger.info(f'main 035 - init fuzzer : { fuzzer }, fuzzer_success : { tsFuzzers[fuzzer].S }, fuzzer_fail : { tsFuzzers[fuzzer].F } total_run_time : {tsFuzzers[fuzzer].total_runTime} )')

    # setup fuzzers
    for fuzzer in FUZZERS:
        if ARGS.focus_one and fuzzer != ARGS.focus_one: continue
        logger.info(f'main 036 - warm up {fuzzer}')
        CPU_ASSIGN[fuzzer] = 0
        if ARGS.enfuzz:
            # handle speical case for enfuzz, which will only use 1 CPU per fuzzer
            # although it will be paused later
            j = math.ceil(JOBS / len(FUZZERS))
            start(fuzzer=fuzzer,
                  output_dir=OUTPUT,
                  timeout=timeout,
                  jobs=j,
                  input_dir=INPUT,
                  empty_seed=ARGS.empty_seed)
        else:
            start(fuzzer=fuzzer,
                  output_dir=OUTPUT,
                  timeout=timeout,
                  jobs=JOBS,
                  input_dir=INPUT,
                  empty_seed=ARGS.empty_seed)

        coverage.thread_run_fuzzer(TARGET,
                                   fuzzer,
                                   FUZZERS,
                                   OUTPUT,
                                   ARGS.timeout,
                                   '10s',
                                   input_dir=INPUT,
                                   empty_seed=ARGS.empty_seed,
                                   crash_mode=ARGS.crash_mode,
                                   input_only=False)
        time.sleep(2)
        start_time = time.time()
        while not check_fuzzer_ready_one(fuzzer):
            current_time = time.time()
            elasp = current_time - start_time
            if elasp > 180:
                logger.critical('fuzzers start up error')
                terminate_autofz()
            logger.info(
                f'main 037 - fuzzer not {fuzzer} ready, sleep 10 seconds to warm up')
            time.sleep(2)

        # pause current fuzzer and wait others to start up
        if not ARGS.focus_one:
            pause(fuzzer=fuzzer,
                  jobs=JOBS,
                  input_dir=INPUT,
                  empty_seed=ARGS.empty_seed)

    LOG_DATETIME = f'{datetime.datetime.now():%Y-%m-%d-%H-%M-%S}'
    LOG_FILE_NAME = f'{TARGET}_{LOG_DATETIME}.json'

    thread_fuzzer_log = threading.Thread(target=thread_update_fuzzer_log,
                                         kwargs={'fuzzers': FUZZERS},
                                         daemon=True)



    thread_fuzzer_log.start()

    thread_health = threading.Thread(target=thread_health_check, daemon=True)
    thread_health.start()

    scheduler = None
    algorithm = None

    # foucs one fuzzer; equal to running a single individual fuzzer
    if ARGS.focus_one:
        scheduler = Schedule_Focus(fuzzers=FUZZERS, focus=ARGS.focus_one)
        algorithm = ARGS.focus_one
    # EnFuzz mode
    elif ARGS.enfuzz:
        scheduler = Schedule_EnFuzz(fuzzers=FUZZERS,
                                    sync_time=ARGS.enfuzz,
                                    jobs=JOBS)
        algorithm = 'enfuzz'
    # autofz mode
    else:
        diff_threshold = ARGS.diff_threshold
        scheduler = Schedule_Autofz(fuzzers=FUZZERS,tsFuzzers=tsFuzzers,
                                      prep_time=PREP_TIME,
                                      focus_time=FOCUS_TIME,
                                      diff_threshold=diff_threshold)
        algorithm = 'autofz'

    assert scheduler
    assert algorithm

    LOG['algorithm'] = algorithm

    RUNNING = True

    thread_log = threading.Thread(target=thread_write_log, daemon=True)
    thread_log.start()

    # Timer to stop all fuzzers
    logger.info(f'main 038 - algorithm : {algorithm}, scheduler: {scheduler}')

    scheduler.run()

    finish_path = os.path.join(OUTPUT, 'finish')
    pathlib.Path(finish_path).touch(mode=0o666, exist_ok=True)
    while not is_end_global():
        logger.info('main 039 - sleep to wait final coverage')
        time.sleep(300)

    LOG['end_time'] = time.time()

    write_log()
    logger.info('main 040 - autofz terminating')
    cleanup(0)


if __name__ == '__main__':
    main()
