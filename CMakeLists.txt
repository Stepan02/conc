cmake_minimum_required(VERSION 3.28)
project(conc C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_EXTENSIONS ON)

find_package(PkgConfig REQUIRED)
pkg_check_modules(ARCHIVE REQUIRED libarchive)

add_executable(conc main.c
        filesystem/rootfs.c
        filesystem/fs.h
        filesystem/overlayfs.c)

target_link_libraries(conc PRIVATE ${ARCHIVE_LIBRARIES})
target_include_directories(conc PRIVATE ${ARCHIVE_INCLUDE_DIRS})
