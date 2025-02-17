ARG FUZZER_PREFIX
ARG BENCHMARK_PREFIX
FROM $BENCHMARK_PREFIX/magma as bench_magma
FROM $FUZZER_PREFIX/angora

RUN mkdir -p /d/p/angora

COPY --from=bench_magma /d/p/normal /d/p normal

COPY source/ /autofz_bench

RUN cd /autofz_bench/magma

COPY magma-angora/build_all.sh /

RUN /build_all.sh
