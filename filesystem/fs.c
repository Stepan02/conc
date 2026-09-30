#include "fs.h"
#include <sched.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <archive.h>

char merged[PATH_MAX + 32];

int copy_file(const char *source_path, const char *destination_path) {
    const int source_fd = open(source_path, O_RDONLY);
    if (source_fd == -1) {
        perror("open src file");
        return -1;
    }

    struct stat st;
    if (fstat(source_fd, &st) < 0) {
        close(source_fd);
        return -1;
    }

    const int destination_fd = open(destination_path, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode);
    if (destination_fd < 0) {
        perror("open target path");
        close(source_fd);
        return -1;
    }

    char file_buffer[8192];
    ssize_t bytes;
    while ((bytes = read(source_fd, file_buffer, sizeof(file_buffer))) > 0) {
        if (write(destination_fd, file_buffer, bytes) != bytes) {
            perror("write file");
            close(source_fd);
            close(destination_fd);
            return -1;
        }
    }

    close(source_fd);
    close(destination_fd);
    return 0;
}

int remove_directory(const char *path) {
    DIR *d = opendir(path);
    if (!d) {
        return -1;
    }

    size_t path_len = strlen(path);
    int r = 0;
    struct dirent *p;

    while ((p = readdir(d)) != NULL) {
        if (!strcmp(p->d_name, ".") || !strcmp(p->d_name, ".."))
            continue;

        const size_t len = path_len + strlen(p->d_name) + 2;
        char *buf = malloc(len);
        if (!buf) {
            r = -1;
            continue;
        }

        snprintf(buf, len, "%s/%s", path, p->d_name);

        struct stat st;
        int r2 = 0;

        if (lstat(buf, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                r2 = remove_directory(buf);
            } else {
                r2 = unlink(buf);
            }
        } else {
            r2 = -1;
        }

        free(buf);

        if (r2 < 0) {
            r = -1;
        }
    }
    closedir(d);

    if (r == 0) {
        r = rmdir(path);
    }

    return r;
}

int unmount_fs(const char *container_name) {
    snprintf(merged, sizeof(merged), "/tmp/runner-%s/merged", container_name);
    char base_directory[PATH_MAX];
    snprintf(base_directory, sizeof(base_directory), "/tmp/runner-%s", container_name);

    // unmount merged directory
    if (umount2(merged, MNT_DETACH) == -1 && errno != EINVAL && errno != ENOENT) {
        perror("umount merged");
    }

    // unmount tmpfs
    if (umount2(base_directory, MNT_DETACH) == -1 && errno != EINVAL && errno != ENOENT) {
        perror("umount tmpfs");
        return -1;
    }

    return 0;
}

int mount_overlayfs(const char *rootfs_path, const char *container_name, const int disk_limit) {
    char base_directory[PATH_MAX];
    char upper_directory[PATH_MAX + 32];
    char work_directory[PATH_MAX + 32];

    snprintf(base_directory, sizeof(base_directory), "/tmp/runner-%s", container_name);
    snprintf(upper_directory, sizeof(upper_directory), "%s/upper", base_directory);
    snprintf(work_directory, sizeof(work_directory), "%s/work", base_directory);
    snprintf(merged, sizeof(merged), "%s/merged", base_directory);

    // create base directory
    if (mkdir(base_directory, 0700) == -1 && errno != EEXIST) {
        perror("mkdir base");
        return -1;
    }

    // set disk limit
    char mount_options[64];
    snprintf(mount_options, sizeof(mount_options), "size=%dM", disk_limit);
    if (mount("tmpfs", base_directory, "tmpfs", 0, mount_options) == -1) {
        perror("mount tmpfs");
        return -1;
    }

    if (mkdir(upper_directory, 0755) == -1) {
        perror("mkdir upperdir");
        return -1;
    }

    if (mkdir(work_directory, 0755) == -1) {
        perror("mkdir workdir");
        return -1;
    }

    if (mkdir(merged, 0755) == -1) {
        perror("mkdir merged");
        return -1;
    }

    struct stat st_base;
    if (stat(base_directory, &st_base) == -1) {
        perror("stat base dir");
        return -1;
    }

    char lower_directory_layer[PATH_MAX + 32];
    char upper_directory_layer[PATH_MAX + 64];
    char work_directory_layer[PATH_MAX + 64];

    snprintf(lower_directory_layer, sizeof(lower_directory_layer), "lowerdir=%s", rootfs_path);
    snprintf(upper_directory_layer, sizeof(upper_directory_layer), "upperdir=%s", upper_directory);
    snprintf(work_directory_layer, sizeof(work_directory_layer), "workdir=%s", work_directory);

    pid_t fpid = fork(); // fuse-overlayfs pid
    if (fpid == -1) {
        perror("fork fuse-overlayfs");
        return -1;
    }

    if (fpid == 0) {
        execlp("fuse-overlayfs", "fuse-overlayfs",
               "-o", lower_directory_layer,
               "-o", upper_directory_layer,
               "-o", work_directory_layer,
               merged, (char *) NULL);

        perror("execlp fuse-overlayfs failed");
        _exit(1);
    }

    waitpid(fpid, NULL, 0);

    struct stat st_merged;
    int mounted = 0;

    // wait for fuse
    for (int check = 0; check < 20; check++) {
        usleep(50000); // 50 ms
        if (stat(merged, &st_merged) == 0 && st_merged.st_dev != st_base.st_dev) {
            mounted = 1;
            break;
        }
    }

    if (!mounted) {
        fprintf(stderr, "fuse-overlayfs check failed: directory is not mounted\n");
        return -1;
    }

    return 0;
}
