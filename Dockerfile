FROM ubuntu:22.04 AS builder

# download dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    cmake \
    build-essential \
    libseccomp-dev \
    libarchive-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY . /build

# compile runner
RUN cmake -B . -DCMAKE_BUILD_TYPE=Release && \
    cmake --build . -j$(nproc)

FROM ubuntu:22.04

# download dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    fuse-overlayfs \
    libseccomp2 \
    libarchive13 \
    curl \
    ca-certificates \
    tar \
    && rm -rf /var/lib/apt/lists/*

# download example alpine rootfs tarball
RUN curl -L https://dl-cdn.alpinelinux.org/alpine/v3.20/releases/x86_64/alpine-minirootfs-3.20.0-x86_64.tar.gz -o /opt/alpine.tar

# download example ubuntu rootfs tarball
RUN curl -L https://cdimage.ubuntu.com/ubuntu-base/jammy/daily/current/jammy-base-amd64.tar.gz -o /opt/ubuntu.tar.gz

# create runner user
RUN useradd -ms /bin/bash runner

# add compiled runner
COPY --from=builder /build/runner /usr/bin/runner
CMD ["/bin/bash"]