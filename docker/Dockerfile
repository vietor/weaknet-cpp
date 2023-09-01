FROM ubuntu:20.04 as base

RUN set -ex; \
    apt-get update; \
    apt-get install -y cmake g++ libevent-dev libsodium-dev libssl-dev

###############################

FROM base as builder

WORKDIR /code
COPY ./src /code/src
COPY ./cmake /code/cmake
COPY ./CMakeLists.txt /code

RUN set -ex; \
    cmake -DCMAKE_BUILD_TYPE=Release .; \
    make

###############################

FROM ubuntu:20.04

RUN set -ex; \
    apt-get update; \
    apt-get install -y libevent-2.1-7 libsodium23 openssl; \
    apt-get clean autoclean; \
    rm -rf /var/lib/apt/lists/

COPY --from=builder /code/weaknet-* /usr/bin/
