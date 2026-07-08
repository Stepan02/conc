FROM ubuntu:latest

# install dependencies
RUN apt-get update && apt-get install -y \
    libc6 \
    libcap2 \
    pkg-config \
    libarchive-dev \
    strace \
    iproute2 \
    && rm -rf /var/lib/apt/lists/*

# set working directory
WORKDIR /test

# download filesystem
RUN mkdir -p /opt/images/alpine
ADD https://dl-cdn.alpinelinux.org/alpine/v3.18/releases/x86_64/alpine-minirootfs-3.18.4-x86_64.tar.gz /opt/images/alpine/alpine-rootfs.tar