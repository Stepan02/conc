cmake_minimum_required(VERSION 3.22)
project(runner C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

add_compile_definitions(_GNU_SOURCE)

add_executable(runner main.c
        filesystem/fs.h
        filesystem/fs.c
        sandbox/resources.h
        sandbox/resources.c
        sandbox/security.h
        sandbox/security.c
        sandbox/network.h
        sandbox/network.c
        sandbox/user.h
        sandbox/user.c
        sandbox/ipc.c
        sandbox/ipc.h)

find_package(PkgConfig REQUIRED)
pkg_check_modules(SYSTEMD REQUIRED libsystemd)

target_include_directories(runner PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${SYSTEMD_INCLUDE_DIRS})

target_link_libraries(runner PRIVATE seccomp archive ${SYSTEMD_LIBRARIES})