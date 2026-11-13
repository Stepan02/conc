#include "user.h"
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <sys/wait.h>
#include "include/types.h"

int map_user(const pid_t child_pid, const id_mapping_t *uid_mappings, const int uid_mappings_count, const id_mapping_t *gid_mappings, const int gid_mappings_count) {
    // use uid_map and gid_map if running as root
    if (geteuid() == 0) {
        char path[64];

        // map container uid to host uid
        snprintf(path, sizeof(path), "/proc/%d/uid_map", child_pid);
        int fd = open(path, O_WRONLY);
        if (fd < 0) {
            perror("open uid_map");
            return -1;
        }

        char uid_buffer[4096] = {0};
        int uid_offset = 0;
        for (int i = 0; i < uid_mappings_count; i++) {
            const int written = snprintf(uid_buffer + uid_offset, sizeof(uid_buffer) - uid_offset,
                "%u %u %u\n",
                uid_mappings[i].container_id,
                uid_mappings[i].host_id,
                uid_mappings[i].size);

            if (written > 0) {
                uid_offset += written;
            }
        }

        if (write(fd, uid_buffer, uid_offset) < 0) {
            perror("write uid_map");
            close(fd);
            return -1;
        }

        close(fd);

        // map container gid to host gid
        snprintf(path, sizeof(path), "/proc/%d/gid_map", child_pid);
        fd = open(path, O_WRONLY);
        if (fd < 0) {
            perror("open gid_map");
            return -1;
        }

        char gid_buffer[4096] = {0};
        int gid_offset = 0;
        for (int i = 0; i < gid_mappings_count; i++) {
            const int written = snprintf(gid_buffer + gid_offset, sizeof(gid_buffer) - gid_offset,
                "%u %u %u\n",
                gid_mappings[i].container_id,
                gid_mappings[i].host_id,
                gid_mappings[i].size);

            if (written > 0) {
                gid_offset += written;
            }
        }

        if (write(fd, gid_buffer, gid_offset) < 0) {
            perror("write gid_map");
            close(fd);
            return -1;
        }

        close(fd);

        return 0;
    }

    char pid_str[32];
    char host_uid_str[32];
    char host_gid_str[32];

    // get uid and gid from host
    const uid_t host_uid = getuid();
    const gid_t host_gid = getgid();

    // convert child pid, host uid and host gid to string
    snprintf(pid_str, sizeof(pid_str), "%d", child_pid);
    snprintf(host_uid_str, sizeof(host_uid_str), "%d", host_uid);
    snprintf(host_gid_str, sizeof(host_gid_str), "%d", host_gid);

    // map container uid to host uid
    pid_t pid = fork();
    if (pid == 0) {
        execlp("newuidmap", "newuidmap", pid_str,
            "0", host_uid_str, "1", // root
            "1", "100000", "65536", // other users
            NULL);
        perror("execlp newuidmap");
        _exit(1);
    }

    int status;
    waitpid(pid, &status, 0);
    if (status != 0) {
        return -1;
    }

    // map container gid to host gid
    pid = fork();
    if (pid == 0) {
        execlp("newgidmap", "newgidmap", pid_str,
            "0", host_gid_str, "1", // root
            "1", "100000", "65536",  // other users
            NULL);
        perror("execlp newgidmap");
        _exit(1);
    }

    waitpid(pid, &status, 0);
    if (status != 0) {
        return -1;
    }

    return 0;
}
