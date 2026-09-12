#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>

int map_user(pid_t child_pid) {
    char path[256];
    char map_data[64];

    // get uid and gid from host
    uid_t host_uid = getuid();
    gid_t host_gid = getgid();

    // map container uid 0 to host uid
    snprintf(path, sizeof(path), "/proc/%d/uid_map", child_pid);
    int fd = open(path, O_WRONLY);
    if (fd == -1) {
        perror("open uid_map");
        return -1;
    }

    int len = snprintf(map_data, sizeof(map_data), "0 %d 1\n", host_uid);
    if (write(fd, map_data, len) != len) {
        perror("write uid_map");
        close(fd);
        return -1;
    }

    close(fd);

    // deny setgroups
    snprintf(path, sizeof(path), "/proc/%d/setgroups", child_pid);
    fd = open(path, O_WRONLY);
    if (fd != -1) {
        write(fd, "deny", 4);
        close(fd);
    }

    // map container gid 0 to host gid
    snprintf(path, sizeof(path), "/proc/%d/gid_map", child_pid);
    fd = open(path, O_WRONLY);
    if (fd == -1) {
        perror("open gid_map");
        return -1;
    }

    len = snprintf(map_data, sizeof(map_data), "0 %d 1\n", host_gid);
    if (write(fd, map_data, len) != len) {
        perror("write gid_map");
        close(fd);
        return -1;
    }

    close(fd);

    return 0;
}
