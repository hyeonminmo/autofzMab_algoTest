import numpy as np
import logging

logger = logging.getLogger('autofz.thompson')

class fuzzer():
    def __init__(self):
        self.S = 1 # success count
        self.F = 1 # fail count
        self.prob = 0.0
        self.total_runTime = 0

def selectFuzzer(fuzzers):
    selectedFuzzers =[]
    for value in fuzzers.values():
        value.prob = np.random.beta(value.S, value.F, size = 1)
        logger.info(f'thomps 001 - Success: { value.S }, Fail : {value.F}, Prob: { value.prob }')

    max_prob_fuzzer = max(fuzzers, key=lambda key: fuzzers[key].prob)
    selectedFuzzers.append(max_prob_fuzzer)

    logger.info(f'thomps 002 - selected Fuzzers: {selectedFuzzers}')
    return selectedFuzzers

def updateFuzzerCount(tsfuzzer, selected_fuzzers, criteria):
    for selected_fuzzer in selected_fuzzers:
        fuzzer = tsfuzzer[selected_fuzzer]
        if criteria == 1:
            fuzzer.S = fuzzer.S + 1
            logger.info(f'thomps 003 - {fuzzer} is success')
        else:
            fuzzer.F = fuzzer.F + 1
            logger.info(f'thomps 004 - {fuzzer} is fail')

def updateFuzzerCountPrep(tsfuzzer, selected_fuzzer, criteria):
    fuzzer = tsfuzzer[selected_fuzzer]
    if criteria == 1:
        fuzzer.S = fuzzer.S + 1
        logger.info(f'thomps 005 - {fuzzer} is success')
    else:
        fuzzer.F = fuzzer.F + 1
        logger.info(f'thomps 006 - {fuzzer} is fail')
    
