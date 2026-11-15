#include "user.h"
#include <fcntl.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
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

    // convert child pid to string
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d", child_pid);

    // map container uid to host uid
    int total_args = 2 + (uid_mappings_count * 3) + 1; // get total args for newuidmap call - 3 strings per mapping and null termination
    char **uidmap_args = malloc(total_args * sizeof(char *));
    if (!uidmap_args) {
        perror("malloc newuidmap args");
        return -1;
    }

    uidmap_args[0] = "newuidmap";
    uidmap_args[1] = pid_str;

    // assign mappings
    int args_idx = 2;
    for (int i = 0; i < uid_mappings_count; i++) {
        char *c_id = malloc(32);
        char *h_id = malloc(32);
        char *sz = malloc(32);

        snprintf(c_id, 32, "%u", uid_mappings[i].container_id);
        snprintf(h_id, 32, "%u", uid_mappings[i].host_id);
        snprintf(sz, 32, "%u", uid_mappings[i].size);

        uidmap_args[args_idx++] = c_id;
        uidmap_args[args_idx++] = h_id;
        uidmap_args[args_idx++] = sz;
    }

    uidmap_args[args_idx++] = NULL; // add null termination

    // map container uid to host uid
    pid_t pid = fork();
    if (pid == 0) {
        execvp("newuidmap", uidmap_args);
        perror("execvp newuidmap");
        _exit(1);
    }

    int uid_map_status;
    waitpid(pid, &uid_map_status, 0);

    // args cleanup
    for (int i = 2; i < args_idx; i++) {
        free(uidmap_args[i]);
    }
    free(uidmap_args);

    if (uid_map_status != 0) {
        return -1;
    }

    // map container gid to host gid
    total_args = 2 + (gid_mappings_count * 3) + 1; // get total args for newgidmap call - 3 strings per mapping and null termination
    char **gidmap_args = malloc(total_args * sizeof(char *));
    if (!gidmap_args) {
        perror("malloc newgidmap args");
        return -1;
    }

    gidmap_args[0] = "newgidmap";
    gidmap_args[1] = pid_str;

    // assign mappings
    args_idx = 2;
    for (int i = 0; i < gid_mappings_count; i++) {
        char *c_id = malloc(32);
        char *h_id = malloc(32);
        char *sz = malloc(32);

        snprintf(c_id, 32, "%u", gid_mappings[i].container_id);
        snprintf(h_id, 32, "%u", gid_mappings[i].host_id);
        snprintf(sz, 32, "%u", gid_mappings[i].size);

        gidmap_args[args_idx++] = c_id;
        gidmap_args[args_idx++] = h_id;
        gidmap_args[args_idx++] = sz;
    }

    gidmap_args[args_idx++] = NULL; // add null termination

    // map container gid to host gid
    pid = fork();
    if (pid == 0) {
        execvp("newgidmap", gidmap_args);
        perror("execvp newgidmap");
        _exit(1);
    }

    int gid_map_status;
    waitpid(pid, &gid_map_status, 0);

    // args cleanup
    for (int i = 2; i < args_idx; i++) {
        free(gidmap_args[i]);
    }
    free(gidmap_args);

    if (gid_map_status != 0) {
        return -1;
    }

    return 0;
}
