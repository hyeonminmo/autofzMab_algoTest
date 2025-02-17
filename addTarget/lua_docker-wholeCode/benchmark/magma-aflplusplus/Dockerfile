ARG FUZZER_PREFIX
FROM $FUZZER_PREFIX/aflplusplus

RUN mkdir /d

COPY source/ /autofz_bench

RUN cd /autofz_bench/magma-aflplusplus

COPY magma-aflplusplus/build_all.sh /

RUN /build_all.sh
