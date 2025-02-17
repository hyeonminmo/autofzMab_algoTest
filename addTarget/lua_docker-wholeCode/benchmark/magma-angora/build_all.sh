#!/bin/bash

MAGMA_DIR=/autofz_bench/magma-angora

magma_targets=(
    lua
)

export RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PIN_ROOT=/pin-3.7-97619-g0d0c92f4f-gcc-linux \
    GOPATH=/go \
    PATH=/clang+llvm/bin:/usr/local/cargo/bin:/fuzzer/angora/bin/:/go/bin:$PATH \
    LD_LIBRARY_PATH=/clang+llvm/lib:$LD_LIBRARY_PATH


BUILD_DIR=/autofz_bench/magma-build
mkdir -p $BUILD_DIR /autofz_bench/magma-seeds
OUT_DIR=$BUILD_DIR/out
SHARED_DIR=$BUILD_DIR/shared

mkdir -p $OUT_DIR
mkdir -p $SHARED_DIR

cd $BUILD_DIR


JOBS="-l$(nproc)" # make -j
export JOBS

# Don't create taint rule list for the following libraries
    LIB_BLACKLIST="libgcc_s.so|libstdc++.so|libc.so|libm.so|libpthread.so"

    # Extract and process shared library list
    ldd /d/p/normal/*/*/* | grep '\.so' | awk '{print $3}' | grep '\.so' | sort | uniq \
        | sed 's#^/lib#/usr/lib#g' | sed 's#\.so.*$#.so#g' \
        | grep -Ev "$LIB_BLACKLIST" \
        | xargs -I {} "$FUZZER/repo/tools/gen_library_abilist.sh" '{}' discard > "$TARGET/repo/abilist.txt"

export ANGORA_TAINT_RULE_LIST=/tmp/abilist.txt


for target in ${magma_targets[@]};
do
    {
        echo "Build $target"
        # build with asan off
        OUT_DIR=$BUILD_DIR/$target/out_angoraFast
        SHARED_DIR=$BUILD_DIR/$target/shared_angoraFast
        CC=/fuzzer/angora/bin/angora-clang
        CXX=/fuzzer/angora/bin/angora-clang++
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
        mkdir -p $RUNDIR/out_angoraFast
        mkdir -p $RUNDIR/shared_angoraFast
        pushd .        
        cd $RUNDIR

        $MAGMA_PREINSTALL > /dev/null
        $MAGMA_PREBUILD > /dev/null
        $TARGET_PREINSTALL > /dev/null
        $GITCLONE_SCRIPT > /dev/null
        $MAGMA_APPLYPATCH > /dev/null        
        $BUILD_SCRIPT > /dev/null

        NEW_DIR=/d/p/angora/fast/magma/$target
        NEW_PATH=$NEW_DIR/$target
        mkdir -p $NEW_DIR
        mv $OUT_DIR/$target $NEW_PATH

        popd

        # build with asan on
        CC=/fuzzer/angora/bin/angora-clang
        CXX=/fuzzer/angora/bin/angora-clang++
        CFLAGS='-O2 -fno-omit-frame-pointer'
        CXXFLAGS="$CFLAGS -stdlib=libc++"
        FUZZING_ENGINE=coverage
        AFL_SRC=/fuzzer/afl
        LIBFUZZER_SRC=/llvm/compiler-rt-12.0.0.src/lib/fuzzer/

        # magma environment
        OUT_DIR=$BUILD_DIR/$target/out_angoraTaint
        SHARED_DIR=$BUILD_DIR/$target/shared_angoraTaint
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
        mkdir -p $RUNDIR/out_angoraTaint
        mkdir -p $RUNDIR/shared_angoraTaint
        pushd .
        cd $RUNDIR

        $MAGMA_PREINSTALL > /dev/null
        $MAGMA_PREBUILD > /dev/null
        $TARGET_PREINSTALL > /dev/null
        $GITCLONE_SCRIPT > /dev/null
        $MAGMA_APPLYPATCH > /dev/null
        USE_TRACK=1 $BUILD_SCRIPT > /dev/null

        NEW_DIR=/d/p/angora/taint/magma/$target
        NEW_PATH=$NEW_DIR/$target
        mkdir -p $NEW_DIR
        mv $OUT_DIR/$target $NEW_PATH

        popd

    } &
done
wait

ls -alh /d/p/*
