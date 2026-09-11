FROM ubuntu:22.04 AS builder

# download dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libseccomp-dev \
    libarchive-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . /build

# compile runner
RUN gcc -O3 main.c  \
    filesystem/fs.c  \
    sandbox/resources.c  \
    sandbox/security.c  \
    sandbox/network.c \
    -o runner  \
    -lseccomp \
    -larchive

FROM ubuntu:22.04

# download dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    fuse-overlayfs \
    libseccomp2 \
    libarchive13 \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# download example alpine rootfs tarball
RUN curl -L https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.0-x86_64.tar.gz -o /opt/alpine.tar

# download example ubuntu rootfs tarball
RUN curl -L https://cdimage.ubuntu.com/ubuntu-base/jammy/daily/current/jammy-base-amd64.tar.gz -o /opt/ubuntu.tar.gz

# add compiled runner
COPY --from=builder /build/runner /usr/bin/runner
CMD ["/bin/bash"]