# TT-METAL UBUNTU 20.04 AMD64 DOCKERFILE
FROM ubuntu:20.04

ARG ARCH_NAME

ENV ARCH_NAME=${ARCH_NAME}
ARG DEBIAN_FRONTEND=noninteractive

# Use a newer version of CMake than what is available from Canonical for 20.04
RUN apt -y update \
    && apt install -y --no-install-recommends ca-certificates gpg wget \
    && wget -O - https://apt.kitware.com/keys/kitware-archive-latest.asc 2>/dev/null | gpg --dearmor - | tee /usr/share/keyrings/kitware-archive-keyring.gpg >/dev/null \
    && echo 'deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ focal main' | tee /etc/apt/sources.list.d/kitware.list >/dev/null \
    && rm -rf /var/lib/apt/lists/*

RUN apt -y update && apt install -y apt-utils \
git \
git-lfs \
pkg-config \
cmake=3.22.2-0kitware1ubuntu20.04.1 \
cmake-data=3.22.2-0kitware1ubuntu20.04.1 \
curl \
wget \
libhwloc-dev \
ninja-build \
patchelf

# Install Clang-17
RUN apt install -y lsb-release wget software-properties-common gnupg && wget https://apt.llvm.org/llvm.sh \
    && chmod u+x llvm.sh \
    && ./llvm.sh 17

# Can only be installed after Clang-17 installed
RUN apt-get -y update \
    && apt-get install -y --no-install-recommends \
    libc++-17-dev \
    libc++abi-17-dev \
    && rm -rf /var/lib/apt/lists/*

RUN git clone --recurse-submodules https://github.com/tenstorrent/tt-umd /usr/tt-umd

WORKDIR /usr/tt-umd

RUN cmake -B build -G Ninja -DTT_UMD_BUILD_TESTS=ON -DBUILD_SHARED_LIBS=OFF && cmake --build build --target umd_tests

RUN ln -s build/test/umd/${ARCH_NAME}/unit_tests run_unit_tests && chmod ugo+x run_unit_tests

CMD ["./run_unit_tests"]
