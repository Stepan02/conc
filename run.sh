#!/bin/bash
# compile c code
cmake --build ./cmake-build-debug-wsl --target conc

# docker setup
docker build -t container-test -f Dockerfile .

# docker container run
docker run --privileged --hostname buildcon --rm -it -v "$(pwd)/cmake-build-debug-wsl:/test" container-test /bin/bash