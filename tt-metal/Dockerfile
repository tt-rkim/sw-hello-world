ARG TT_METAL_VERSION=v0.53.0-rc33
FROM ghcr.io/tenstorrent/tt-metal/tt-metalium/ubuntu-20.04-amd64:${TT_METAL_VERSION}-dev

ARG TT_METAL_VERSION
ARG ARCH_NAME
ENV TT_METAL_VERSION=${TT_METAL_VERSION}
ENV DEBIAN_FRONTEND=noninteractive

## install tt-metal from wheel
RUN pip install https://github.com/tenstorrent/tt-metal/releases/download/${TT_METAL_VERSION}/metal_libs-$(echo ${TT_METAL_VERSION} | sed -e 's/[v-]//g')+$(echo ${ARCH_NAME} | sed -e 's/_/./g')-cp38-cp38-linux_x86_64.whl

## add user
RUN adduser --uid 1000 --shell /bin/bash user
USER user
WORKDIR /home/user

CMD python3 -m ttnn.examples.usage.run_op_on_device
