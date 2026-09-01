#include "resources.h"
#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <errno.h>

static int write_file(const char *path, const char *value) {
    FILE *f = fopen(path, "w");
    if (!f) {
        perror(path);
        return -1;
    }
    if (fprintf(f, "%s\n", value) < 0 || fflush(f) != 0) {
        perror(path);
        fclose(f);
        return -1;
    }
    fclose(f);
    return 0;
}

void create_resources(pid_t sandbox_id, int ram_mb, int cpu_us) {
    // allow cgroup controller
    write_file("/sys/fs/cgroup/cgroup.subtree_control", "+memory +cpu +pids +io");

    // create cgroup directory
    char cgroup_path[256];
    snprintf(cgroup_path, sizeof(cgroup_path), "/sys/fs/cgroup/sandbox_%d", sandbox_id);

    if (mkdir(cgroup_path, 0755) == -1 && errno != EEXIST) {
        perror("mkdir cgroup");
        return;
    }

    char file_path[512];
    char val_buf[64];

    // set ram limit
    snprintf(file_path, sizeof(file_path), "%s/memory.max", cgroup_path);
    snprintf(val_buf, sizeof(val_buf), "%lld", (long long)ram_mb * 1024 * 1024);
    write_file(file_path, val_buf);

    // disable swap
    snprintf(file_path, sizeof(file_path), "%s/memory.swap.max", cgroup_path);
    write_file(file_path, "0");

    // set cpu time limit
    snprintf(file_path, sizeof(file_path), "%s/cpu.max", cgroup_path);
    snprintf(val_buf, sizeof(val_buf), "%d 100000", cpu_us);
    write_file(file_path, val_buf);

    // set pid limit to 64 processes
    snprintf(file_path, sizeof(file_path), "%s/pids.max", cgroup_path);
    write_file(file_path, "64");

    // set i/o limit
    struct stat st;
    if (stat("/", &st) == 0) {
        int dev_major = major(st.st_dev);
        int dev_minor = minor(st.st_dev);

        // set i/o limit to 10 mb/s
        snprintf(file_path, sizeof(file_path), "%s/io.max", cgroup_path);
        snprintf(val_buf, sizeof(val_buf), "%d:%d rbps=10485760 wbps=10485760",
                         dev_major, dev_minor);

        if (write_file(file_path, val_buf) != 0) {
            fprintf(stderr, "io.max\n");
        }
    } else {
        perror("stat / failed for io.max");
    }
}

void allocate_resources(pid_t sandbox_id) {
    char file_path[512];
    snprintf(file_path, sizeof(file_path), "/sys/fs/cgroup/sandbox_%d/cgroup.procs", sandbox_id);

    if (write_file(file_path, "0") != 0) {
        fprintf(stderr, "allocate resources\n");
    }
}

void cleanup_resources(pid_t sandbox_id) {
    char cgroup_path[256];
    snprintf(cgroup_path, sizeof(cgroup_path), "/sys/fs/cgroup/sandbox_%d", sandbox_id);
    rmdir(cgroup_path);
}