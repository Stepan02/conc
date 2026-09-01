#define _GNU_SOURCE
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
#include <archive_entry.h>

#define STACK_SIZE (1024 * 1024)
#define MKDIR_OR_FAIL(path, mode) do { \
if (mkdir(path, mode) == -1) { \
if (errno != EEXIST) { \
perror("mkdir " #path); \
return -1; \
} else { \
printf("mkdir %s: already exists\n", path); \
} \
} else { \
printf("mkdir %s: created\n", path); \
} \
} while(0)

char upperdir[256];
char workdir[256];
char merged[256];
char base[256]; // /tmp/runner-<id>

static int copy_data(struct archive *ar, struct archive *aw) {
    const void *buffer;
    size_t size;
    la_int64_t offset;

    for (;;) {
        int reader = archive_read_data_block(ar, &buffer, &size, &offset);

        if (reader == ARCHIVE_EOF) {
            return ARCHIVE_OK;
        }

        if (reader < ARCHIVE_WARN) {
            fprintf(stderr, "%s\n", archive_error_string(ar));
            return reader;
        }

        reader = archive_write_data_block(aw, buffer, size, offset);

        if (reader < ARCHIVE_OK) {
            fprintf(stderr, "%s\n", archive_error_string(aw));
            return reader;
        }
    }
}

static int unzip_fs(const char *path, const char *destination) {
    struct archive_entry *entry;

    printf("unpacking tarball %s\n", path);

    // go to the destination directory
    if (chdir(destination) != 0) {
        printf("creating the destination directory\n");

        if (mkdir(destination, 0755) != 0) {
            perror("error creating the destination directory");
            return -1;
        }

        if (chdir(destination) != 0) {
            perror("cannot change directory to destination");
            return -1;
        }
    }

    const mode_t old_umask = umask(0);

    // select attributes to unzip
    const int flags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM | ARCHIVE_EXTRACT_ACL | ARCHIVE_EXTRACT_FFLAGS | ARCHIVE_EXTRACT_SECURE_NODOTDOT |
                      ARCHIVE_EXTRACT_OWNER | ARCHIVE_EXTRACT_UNLINK | ARCHIVE_EXTRACT_XATTR;

    // setup tarball
    struct archive *tarball = archive_read_new();
    archive_read_support_format_all(tarball);
    archive_read_support_filter_all(tarball);

    // setup disk write
    struct archive *ext = archive_write_disk_new();
    archive_write_disk_set_options(ext, flags);
    archive_write_disk_set_standard_lookup(ext);

    if (archive_read_open_filename(tarball, path, 10240) != ARCHIVE_OK) {
        fprintf(stderr, "%s\n", archive_error_string(tarball));

        archive_read_free(tarball);
        archive_write_free(ext);
        umask(old_umask);
        return -1;
    }

    int r;
    while ((r = archive_read_next_header(tarball, &entry)) != ARCHIVE_EOF) {
        if (r < ARCHIVE_OK) {
            fprintf(stderr, "%s\n", archive_error_string(tarball));

            if (r < ARCHIVE_WARN) {
                break;
            }
        }

        const char *current_path = archive_entry_pathname(entry);
        if (current_path[0] == '/') {
            archive_entry_set_pathname(entry, current_path + 1);
        }

        int reader = archive_write_header(ext, entry);

        if (reader == ARCHIVE_WARN) {
            fprintf(stderr, "%s\n", archive_error_string(ext));
        }

        if (reader < ARCHIVE_OK) {
            fprintf(stderr, "%s\n", archive_error_string(ext));
        } else {
            reader = copy_data(tarball, ext);

            if (reader < ARCHIVE_OK) {
                fprintf(stderr, "%s\n", archive_error_string(ext));
            }
        }

        reader = archive_write_finish_entry(ext);

        if (reader < ARCHIVE_OK) {
            fprintf(stderr, "%s\n", archive_error_string(ext));
        }
    }

    archive_read_close(tarball);
    archive_read_free(tarball);
    archive_write_close(ext);
    archive_write_free(ext);

    umask(old_umask);
    sync();
    printf("filesystem unzipped\n");
    return 0;
}

int create_fs(const char *tarball_path, const int pid) {
    snprintf(base, sizeof(base), "/tmp/runner-%d", pid);

    // create base directory (/tmp/runner-<pid>)
    if (mkdir(base, 0755) == -1 && errno != EEXIST) {
        perror("mkdir base directory");
        return -1;
    }

    // set base to lowerdir (/tmp/runner-<pid>/lower)
    char lower_directory[256];
    snprintf(lower_directory, sizeof(lower_directory), "/tmp/runner-%d/lower", pid);

    if (unzip_fs(tarball_path, lower_directory) == -1) {
        perror("unzip_fs");
        return -1;
    }

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

        size_t len = path_len + strlen(p->d_name) + 2;
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

int mount_fs() {
    char path[256];

    snprintf(path, sizeof(path), "%s/proc", merged);
    MKDIR_OR_FAIL(path, 0555);
    if (mount("proc", path, "proc", 0, NULL) == -1) {
        perror("mount /proc");
        return -1;
    }

    snprintf(path, sizeof(path), "%s/tmp", merged);
    MKDIR_OR_FAIL(path, 0777);
    if (mount("tmpfs", path, "tmpfs", 0, "size=64M") == -1) {
        perror("mount /tmp");
        return -1;
    }

    snprintf(path, sizeof(path), "%s/dev", merged);
    MKDIR_OR_FAIL(path, 0755);
    if (mount("tmpfs", path, "tmpfs", 0, NULL) == -1) {
        perror("mount /dev as tmpfs");
        return -1;
    }

    if (mount("/dev/pts", path, NULL, MS_BIND, NULL) == -1) {
        perror("bind mount /dev/pts");
        return -1;
    }

    return 0;
}

int unmount_fs(int pid) {
    char merged_dir[256];
    snprintf(merged_dir, sizeof(merged_dir), "/tmp/runner-%d/merged", pid);

    char path[256];
    const char *submounts[] = {
        "/dev/pts",
        "/dev/shm",
        "/dev/null",
        "/dev/zero",
        "/dev/random",
        "/dev/urandom",
        "/proc/sys/crypto/fips_enabled",
        "/tmp",
        "/proc"
    };

    for (size_t i = 0; i < sizeof(submounts) / sizeof(submounts[0]); i++) {
        snprintf(path, sizeof(path), "%s%s", merged_dir, submounts[i]);

        if (umount(path) == -1 && errno != ENOENT) {
            perror("umount submount");
        }
    }

    if (umount(merged_dir) == -1 && errno != ENOENT) {
        perror("umount overlayfs merged root");
    }

    pid_t fpid = fork();
    if (fpid == 0) {
        execlp("fusermount3", "fusermount3", "-u", "-z", merged_dir, NULL);
        execlp("fusermount", "fusermount", "-u", "-z", merged_dir, NULL);
        _exit(0);
    } else if (fpid > 0) {
        waitpid(fpid, NULL, 0);
    }

    return 0;
}

int mount_overlayfs(int pid) {
    char lower_directory[512], upper_directory[512], work_directory[512], unzipped_fs[256];

    snprintf(unzipped_fs, sizeof(unzipped_fs), "/tmp/runner-%d/lower", pid);
    snprintf(upperdir, sizeof(upperdir), "/tmp/runner-%d/upper", pid);
    snprintf(workdir, sizeof(workdir), "/tmp/runner-%d/work", pid);
    snprintf(merged, sizeof(merged), "/tmp/runner-%d/merged", pid);

    snprintf(lower_directory, sizeof(lower_directory), "lowerdir=%s", unzipped_fs);
    snprintf(upper_directory, sizeof(upper_directory), "upperdir=%s", upperdir);
    snprintf(work_directory, sizeof(work_directory), "workdir=%s", workdir);

    MKDIR_OR_FAIL(upperdir, 0755);
    MKDIR_OR_FAIL(workdir, 0755);
    MKDIR_OR_FAIL(merged, 0755);

    struct stat st_base;
    if (stat(base, &st_base) == -1) {
        perror("stat base dir");
        return -1;
    }

    pid_t fpid = fork(); // fuse-overlayfs pid
    if (fpid == -1) {
        perror("fork fuse-overlayfs");
        return -1;
    }

    if (fpid == 0) {
        execlp("fuse-overlayfs", "fuse-overlayfs",
               "-o", lower_directory,
               "-o", upper_directory,
               "-o", work_directory,
               merged, (char *) NULL);

        perror("execlp fuse-overlayfs failed");
        _exit(1);
    }

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

    printf("fuse-overlayfs mount succeeded\n");
    return 0;
}
