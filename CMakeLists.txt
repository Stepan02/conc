cmake_minimum_required(VERSION 3.28)
project(runner C)

set(CMAKE_C_STANDARD 11)

add_executable(runner main.c
        filesystem/fs.h
        filesystem/fs.c
        sandbox/resources.h
        sandbox/resources.c
        sandbox/security.h
        sandbox/security.c
        sandbox/network.h
        sandbox/network.c)
