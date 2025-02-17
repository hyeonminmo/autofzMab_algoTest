#!/bin/bash

MAGMA_DIR=/autofz_bench/magma

magma_targets=(
    lua
)
mkdir -p /d/p/justafl /d/p/aflasan /d/p/normal /d/p/cov
BUILD_DIR=/autofz_bench/magma-build
mkdir -p $BUILD_DIR /autofz_bench/magma-seeds
OUT_DIR=$BUILD_DIR/out
SHARED_DIR=$BUILD_DIR/shared

mkdir -p $OUT_DIR
mkdir -p $SHARED_DIR

cd $BUILD_DIR

MAGMA_DIR=/autofz_bench/magma

JOBS="-l$(nproc)" # make -j
export JOBS

for target in ${magma_targets[@]};
do
    {
        # build with asan off
        CC=clang
        CXX=clang++
        CFLAGS='-O2 -fno-omit-frame-pointer -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div'
        CXXFLAGS="$CFLAGS -stdlib=libc++"
        FUZZING_ENGINE=afl
        AFL_SRC=/fuzzer/afl
        LIBFUZZER_SRC=/llvm/compiler-rt-12.0.0.src/lib/fuzzer/

        # magma environment
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
        pushd .
        
        cd $RUNDIR
        $MAGMA_PREINSTALL > /dev/null
        $MAGMA_PREBUILD > /dev/null
        $TARGET_PREINSTALL > /dev/null
        $GITCLONE_SCRIPT > /dev/null
        $MAGMA_APPLYPATCH > /dev/null        
        $BUILD_SCRIPT > /dev/null

        NEW_DIR=/d/p/justafl/magma/$target
        NEW_PATH=$NEW_DIR/$target
        mkdir -p $NEW_DIR
        mv $OUT_DIR/$target $NEW_PATH

        popd

        # build with asan on
        CC=clang
        CXX=clang++
        CFLAGS='-O2 -fno-omit-frame-pointer -fsanitize=address -fsanitize-address-use-after-scope -fsanitize-coverage=trace-pc-guard,trace-cmp,trace-gep,trace-div'
        CXXFLAGS="$CFLAGS -stdlib=libc++"
        FUZZING_ENGINE=afl
        AFL_SRC=/fuzzer/afl
        LIBFUZZER_SRC=/llvm/compiler-rt-12.0.0.src/lib/fuzzer/
        # magma environment
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
        pushd .
        cd $RUNDIR

        $MAGMA_PREINSTALL > /dev/null
        $MAGMA_PREBUILD > /dev/null
        $TARGET_PREINSTALL > /dev/null
        $GITCLONE_SCRIPT > /dev/null
        $MAGMA_APPLYPATCH > /dev/null
        $BUILD_SCRIPT > /dev/null

        NEW_DIR=/d/p/aflasan/magma/$target
        NEW_PATH=$NEW_DIR/$target
        mkdir -p $NEW_DIR
        mv $OUT_DIR/$target $NEW_PATH

        popd

        # build normal binary
        CC=clang
        CXX=clang++
        CFLAGS='-O2 -fno-omit-frame-pointer'
        CXXFLAGS="$CFLAGS -stdlib=libc++"
        FUZZING_ENGINE=coverage
        AFL_SRC=/fuzzer/afl
        LIBFUZZER_SRC=/llvm/compiler-rt-12.0.0.src/lib/fuzzer/

        # magma environment
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
        pushd .
        cd $RUNDIR

        $MAGMA_PREINSTALL > /dev/null
        $MAGMA_PREBUILD > /dev/null
        $TARGET_PREINSTALL > /dev/null
        $GITCLONE_SCRIPT > /dev/null
        $MAGMA_APPLYPATCH > /dev/null
        $BUILD_SCRIPT > /dev/null

        NEW_DIR=/d/p/normal/magma/$target
        NEW_PATH=$NEW_DIR/$target
        mkdir -p $NEW_DIR
        mv $OUT_DIR/$target $NEW_PATH

        popd
    } &
done
wait

for target in ${magma_targets[@]};
do
    {
        echo "build $target"
        RUNDIR="$target"
        mkdir -p $RUNDIR
        # build normal binary
        CC=clang
        CXX=clang++
        CFLAGS='-fprofile-arcs -ftest-coverage'
        CXXFLAGS="$CFLAGS -stdlib=libc++"
        FUZZING_ENGINE=coverage
        AFL_SRC=/fuzzer/afl
        LIBFUZZER_SRC=/llvm/compiler-rt-12.0.0.src/lib/fuzzer/

        # magma environment
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
        pushd .
        cd $RUNDIR

        $MAGMA_PREINSTALL > /dev/null
        $MAGMA_PREBUILD > /dev/null
        $TARGET_PREINSTALL > /dev/null
        $GITCLONE_SCRIPT > /dev/null
        $MAGMA_APPLYPATCH > /dev/null
        $BUILD_SCRIPT > /dev/null

        NEW_DIR=/d/p/cov/magma/$target
        NEW_PATH=$NEW_DIR/$target
        mkdir -p $NEW_DIR
        mv $OUT_DIR/$target $NEW_PATH


        popd
    } &
done
wait


ls -alh /d/p/*
