#!/bin/bash

MAGMA_DIR=/autofz_bench/magma-aflplusplus

magma_targets=(
    lua
)
mkdir -p /d/p/aflclangfast
mkdir -p /d/p/aflclangfastcmplog
BUILD_DIR=/autofz_bench/magma-build

mkdir -p $BUILD_DIR /autofz_bench/magma-seeds

cd $BUILD_DIR

JOBS="-l$(nproc)" # make -j
export JOBS

for target in ${magma_targets[@]};
do
    {
        # build 
        CC=afl-clang-fast
        CXX=afl-clang-fast++
        CFLAGS='-O2 -fno-omit-frame-pointer'
        CXXFLAGS="$CFLAGS -stdlib=libc++"
        FUZZING_ENGINE=aflpp
        AFL_SRC=/fuzzer/afl++
        LIBFUZZER_SRC=/llvm/compiler-rt-12.0.0.src/lib/fuzzer/

        # magma environment
        OUT_DIR=$BUILD_DIR/$target/out_aflclangfast
        SHARED_DIR=$BUILD_DIR/$target/shared_aflclangfast
        MAGMA=$MAGMA_DIR/magma
        OUT=$OUT_DIR
        LD=/usr/bin/ld
        AR=/usr/bin/ar
        AS=/usr/bin/as
        NM=/usr/bin/nm
        RANLIB=/usr/bin/ranlib
        SHARED=$SHAERD_DIR
        TARGET=$target

        export CC CXX CFLAGS CXXFLAGS FUZZING_ENGINE AFL_SRC LIBFUZZER_SRC MAGMA OUT LD AR AS NM RANLIB SHARED TARGET

        MAGMA_PREINSTALL=$MAGMA_DIR/magma/preinstall.sh
        MAGMA_PREBUILD=$MAGMA_DIR/magma/prebuild.sh
        MAGMA_APPLYPATCH=$MAGMA_DIR/magma/apply_patches.sh
        TARGET_PREINSTALL=$MAGMA_DIR/targets/$target/preinstall.sh
        GITCLONE_SCRIPT=$MAGMA_DIR/targets/$target/fetch.sh
        BUILD_SCRIPT=$MAGMA_DIR/targets/$target/build.sh
        RUNDIR="$target"
        mkdir -p $RUNDIR
        mkdir -p $RUNDIR/out_aflclangfast
        mkdir -p $RUNDIR/shared_aflclangfast
        pushd .
        
        cd $RUNDIR
        $MAGMA_PREINSTALL > /dev/null
        $MAGMA_PREBUILD > /dev/null
        $TARGET_PREINSTALL > /dev/null
        $GITCLONE_SCRIPT > /dev/null
        $MAGMA_APPLYPATCH > /dev/null        
        $BUILD_SCRIPT > /dev/null

        NEW_DIR=/d/p/aflclangfast/magma/$target
        NEW_PATH=$NEW_DIR/$target
        mkdir -p $NEW_DIR
        mv $OUT_DIR/$target $NEW_PATH

        popd

        # build with 
        CC=afl-clang-fast
        CXX=afl-clang-fast++
        CFLAGS='-O2 -fno-omit-frame-pointer'
        CXXFLAGS="$CFLAGS -stdlib=libc++"
        FUZZING_ENGINE=aflpp
        AFL_SRC=/fuzzer/afl++
        LIBFUZZER_SRC=/llvm/compiler-rt-12.0.0.src/lib/fuzzer/

        # magma environment
        OUT_DIR=$BUILD_DIR/$target/out_aflclangfastcmplog
        SHARED_DIR=$BUILD_DIR/$target/shared_aflclangfastcmplog
        MAGMA=$MAGMA_DIR/magma
        OUT=$OUT_DIR
        LD=/usr/bin/ld
        AR=/usr/bin/ar
        AS=/usr/bin/as
        NM=/usr/bin/nm
        RANLIB=/usr/bin/ranlib
        SHARED=$SHAERD_DIR
        TARGET=$target

        export CC CXX CFLAGS CXXFLAGS FUZZING_ENGINE AFL_SRC LIBFUZZER_SRC MAGMA OUT LD AR AS NM RANLIB SHARED TARGET
        
        MAGMA_PREINSTALL=$MAGMA_DIR/magma/preinstall.sh
        MAGMA_PREBUILD=$MAGMA_DIR/magma/prebuild.sh
        MAGMA_APPLYPATCH=$MAGMA_DIR/magma/apply_patches.sh
        TARGET_PREINSTALL=$MAGMA_DIR/targets/$target/preinstall.sh
        GITCLONE_SCRIPT=$MAGMA_DIR/targets/$target/fetch.sh
        BUILD_SCRIPT=$MAGMA_DIR/targets/$target/build.sh

        RUNDIR="$target"
        mkdir -p $RUNDIR
        mkdir -p $RUNDIR/out_aflclangfastcmplog
        mkdir -p $RUNDIR/shared_aflclangfastcmplog
        pushd .
        cd $RUNDIR

        $MAGMA_PREINSTALL > /dev/null
        $MAGMA_PREBUILD > /dev/null
        $TARGET_PREINSTALL > /dev/null
        $GITCLONE_SCRIPT > /dev/null
        $MAGMA_APPLYPATCH > /dev/null
        AFL_LLVM_CMPLOG=1 $BUILD_SCRIPT > /dev/null

        NEW_DIR=/d/p/aflclangfastcmplog/magma/$target
        NEW_PATH=$NEW_DIR/$target
        mkdir -p $NEW_DIR
        mv $OUT_DIR/$target $NEW_PATH

        popd
    } &
done
wait

ls -alh /d/p/*
