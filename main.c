#define _GNU_SOURCE
#include <sched.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <pty.h>
#include <string.h>
#include <termios.h>
#include <pwd.h>
#include <grp.h>
#include "filesystem/fs.h"
#include "sandbox/resources.h"
#include "sandbox/security.h"
#include "sandbox/network.h"

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

// global uid, uid and home values
uid_t uid = 0;
gid_t gid = 0;
char home_dir[256] = "/home/runner";

// global hostname variable
char hostname[64];

// global tarball path variable
char tarball_path[1024];

// setup child process stack and script path
static char child_stack[STACK_SIZE];
char *script_path = NULL;

int child_fn(void *arg) {
    int *args = (int *) arg;
    int shell_mode = args[0];
    int ram_limit = args[1];
    int cpu_limit = args[2];
    int parent_pid = args[3];

    // create cgroup
    create_resources(parent_pid, ram_limit, cpu_limit);

    // assign process to cgroup
    allocate_resources(parent_pid);

    setpgid(0, 0);

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        perror("mount MS_PRIVATE");
    }

    snprintf(merged, sizeof(merged), "/tmp/runner-%d/merged", parent_pid);

    char path[256];
    snprintf(path, sizeof(path), "%s/proc", merged);
    if (mount("proc", path, "proc", 0, NULL) == -1) {
        perror("mount /proc");
    }

    snprintf(path, sizeof(path), "%s/tmp", merged);
    mkdir(path, 0777);
    if (mount("tmpfs", path, "tmpfs", 0, "mode=1777") == -1) {
        perror("mount /tmp");
    }

    char fips_path[256];
    snprintf(fips_path, sizeof(fips_path), "%s/proc/sys/crypto/fips_enabled", merged);
    if (access(fips_path, F_OK) == 0) {
        int tmp_fd = open("/tmp/fips_zero", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (tmp_fd != -1) {
            write(tmp_fd, "0\n", 2);
            close(tmp_fd);
            mount("/tmp/fips_zero", fips_path, NULL, MS_BIND, NULL);
        }
    }

    snprintf(path, sizeof(path), "%s/dev", merged);
    mkdir(path, 0755);

    for (int i = 0; i < 4; i++) {
        const char *sys_devs[] = {"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom"};
        snprintf(path, sizeof(path), "%s%s", merged, sys_devs[i]);

        int fd = open(path, O_WRONLY | O_CREAT, 0666);
        if (fd != -1) close(fd);

        if (mount(sys_devs[i], path, NULL, MS_BIND, NULL) == -1) {
            perror(sys_devs[i]);
        }
    }

    snprintf(path, sizeof(path), "%s/dev/bashm", merged);
    mkdir(path, 0777);

    if (mount("tmpfs", path, "tmpfs", 0, "mode=1777") == -1) {
        perror("mount /dev/bashm");
    }

    snprintf(path, sizeof(path), "%s/dev/pts", merged);
    mkdir(path, 0755);

    if (mount("devpts", path, "devpts", 0, "newinstance,mode=0620,ptmxmode=0666") == -1) {
        perror("mount devpts");
    }

    // save old root
    char put_old[256];
    snprintf(put_old, sizeof(put_old), "%s/old_root", merged);
    mkdir(put_old, 0700);

    // check merged mountpoint
    if (mount(merged, merged, NULL, MS_BIND | MS_REC, NULL) == -1) {
        perror("mount bind merged");
        return 1;
    }

    // change root
    if (syscall(SYS_pivot_root, merged, put_old) == -1) {
        perror("pivot_root");
        return 1;
    }

    if (chdir("/") == -1) {
        perror("chdir");
        return 1;
    }

    // detach old root
    if (umount2("/old_root", MNT_DETACH) == -1) {
        perror("umount old_root");
    }

    // remove old root
    rmdir("/old_root");

    unlink("/dev/ptmx");
    if (symlink("/dev/pts/ptmx", "/dev/ptmx") == -1) {
        perror("symlink /dev/ptmx");
    }

    chmod("/dev/ptmx", 0666);
    chmod("/dev/pts", 0755);

    // setup network
    if (setup_loopback() != 0) {
        perror("setup lo");
        return 1;
    }

    pid_t pid = fork();
    if (pid == -1) {
        perror("fork");
        return 1;
    }

    if (pid == 0) {
        // setup hostname and env variables
        if (sethostname(hostname, strlen(hostname)) == -1) {
            perror("hostname");
        }

        setenv("TERM", "xterm-256color", 1);
        setenv("HOME", home_dir, 1);
        setenv("USER", "runner", 1);
        setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);

        if (setsid() == -1) {
            perror("setsid");
            _exit(1);
        }

        // no shell mode
        if (shell_mode == 0) {
            // drop privileges
            if (setgroups(0, NULL) == -1 || setgid(gid) == -1 || setuid(uid) == -1) {
                perror("setgroups");
                _exit(1);
            }

            // init syscall blacklist
            if (setup_syscall_blacklist() != 0) {
                perror("syscall blacklist");
                _exit(1);
            }

            if (access("/bin/sh", X_OK) == -1) {
                perror("sh not executable");
                _exit(1);
            }

            // disable stdin
            int null_fd = open("/dev/null", O_RDONLY);
            if (null_fd != -1) {
                dup2(null_fd, STDIN_FILENO);
                close(null_fd);
            }

            // close descriptors
            for (int fd = 3; fd < 1024; fd++) {
                close(fd);
            }

            // run script if provided
            if (script_path != NULL) {
                execl("/bin/sh", "sh", script_path, (char *) NULL);
            }

            // open shell if no script was provided
            execl("/bin/sh", "sh", NULL);
            perror("execl");
            _exit(1);
        } else {
            int master_fd;
            fprintf(stderr, "launching sh\n");
            fflush(stderr);

            struct winsize w;
            if (ioctl(STDIN_FILENO, TIOCGWINSZ, &w) == -1) {
                w.ws_row = 24;
                w.ws_col = 80;
            }

            pid_t shell_pid = forkpty(&master_fd, NULL, NULL, &w);

            if (shell_pid == -1) {
                perror("forkpty");
                _exit(1);
            }

            if (master_fd < 0) {
                fprintf(stderr, "forkpty returned invalid master_fd\n");
                _exit(1);
            }

            if (shell_pid == 0) {
                // drop privileges
                if (setgroups(0, NULL) == -1 || setgid(gid) == -1 || setuid(uid) == -1) {
                    perror("drop privileges");
                    _exit(1);
                }

                // init syscall blacklist
                if (setup_syscall_blacklist() != 0) {
                    perror("syscall blacklist");
                    _exit(1);
                }

                if (access("/bin/sh", X_OK) == -1) {
                    perror("sh not executable");
                    _exit(1);
                }

                fprintf(stderr, "exec sh\n");

                // close descriptors
                for (int fd = 3; fd < 1024; fd++) {
                    close(fd);
                }

                execl("/bin/sh", "sh", script_path, (char *) NULL);
                perror("execl");
                _exit(1);
            }

            struct termios orig_termios, raw;
            int is_tty = isatty(STDIN_FILENO);

            if (is_tty) {
                tcgetattr(STDIN_FILENO, &orig_termios);
                raw = orig_termios;
                cfmakeraw(&raw);
                tcsetattr(STDIN_FILENO, TCSANOW, &raw);
            }

            fd_set fds;
            char buf[256];
            int maxfd = (master_fd > STDIN_FILENO) ? master_fd : STDIN_FILENO;
            ssize_t n;

            while (1) {
                FD_ZERO(&fds);
                FD_SET(STDIN_FILENO, &fds);
                FD_SET(master_fd, &fds);

                if (select(maxfd + 1, &fds, NULL, NULL, NULL) == -1) {
                    perror("select");
                    break;
                }

                if (FD_ISSET(STDIN_FILENO, &fds)) {
                    n = read(STDIN_FILENO, buf, sizeof(buf));
                    if (n <= 0) break;

                    if (write(master_fd, buf, n) != n) break;
                }

                if (FD_ISSET(master_fd, &fds)) {
                    n = read(master_fd, buf, sizeof(buf));
                    if (n <= 0) break;

                    if (write(STDOUT_FILENO, buf, n) != n) break;
                }
            }

            if (is_tty) {
                tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
            }

            int status;
            waitpid(shell_pid, &status, 0);
            close(master_fd);
        }

        _exit(0);
    } else {
        int status;
        waitpid(pid, &status, 0);

        return 0;
    }
}

int main(int argc, char *argv[]) {
    // init root cgroup
    mkdir("/sys/fs/cgroup/init", 0755);
    FILE *f_init = fopen("/sys/fs/cgroup/init/cgroup.procs", "w");
    if (f_init) {
        fprintf(f_init, "0\n");
        fclose(f_init);
    } else {
        perror("fopen /sys/fs/cgroup/init/cgroup.procs");
    }

    // get uid and gid of runner user
    struct passwd *pw = getpwnam("runner");
    if (pw == NULL) {
        fprintf(stderr, "runner user does not exist\n");
        exit(1);
    }

    uid = pw->pw_uid;
    gid = pw->pw_gid;
    strncpy(home_dir, pw->pw_dir, sizeof(home_dir) - 1);

    // default values
    int shell_mode = 1; // shell runtime is enabled by default (1 = enabled, 0 = disabled)
    int ram_limit = 256; // mb
    int cpu_limit = 100000; // us
    int share_net = 0; // network is isolated by default
    char custom_hostname[64] = "";

    // resolve arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--no-shell") == 0 || strcmp(argv[i], "-nsh") == 0) {
            shell_mode = 0;
        } else if (strcmp(argv[i], "--share-net") == 0 || strcmp(argv[i], "-sn") == 0) {
            share_net = 1;
        } else if (strcmp(argv[i], "--tar") == 0 || strcmp(argv[i], "-t") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing argument for %s\n", argv[i]);
                return 1;
            }
            snprintf(tarball_path, sizeof(tarball_path), "%s", argv[++i]);
        } else if (strcmp(argv[i], "--ram") == 0 || strcmp(argv[i], "-r") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing argument for %s\n", argv[i]);
                return 1;
            }
            ram_limit = (int) strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--cpu") == 0 || strcmp(argv[i], "-c") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing argument for %s\n", argv[i]);
                return 1;
            }
            cpu_limit = (int) strtol(argv[++i], NULL, 10);
        } else if (strcmp(argv[i], "--hostname") == 0 || strcmp(argv[i], "-hn") == 0) {
            if (i + 1 >= argc) {
                fprintf(stderr, "missing argument for %s\n", argv[i]);
                return 1;
            }
            snprintf(custom_hostname, sizeof(custom_hostname), "%s", argv[++i]);
        } else if (argv[i][0] != '-') {
            if (script_path == NULL) {
                script_path = argv[i];
            } else {
                fprintf(stderr, "too many arguments: %s\n", argv[i]);
                return 1;
            }
        } else {
            fprintf(stderr, "unknown option: %s\n", argv[i]);
            return 1;
        }
    }

    // tarball path is required
    if (tarball_path[0] == '\0') {
        fprintf(stderr, "missing tarball path (--tar <path>)\n");
        exit(1);
    }

    int parent_pid = getpid();

    // set hostname
    if (strlen(custom_hostname) > 0) {
        snprintf(hostname, sizeof(hostname), "%s", custom_hostname);
    } else {
        snprintf(hostname, sizeof(hostname), "runner-%d", parent_pid);
    }

    int flags = CLONE_NEWUTS | CLONE_NEWIPC | CLONE_NEWNS | CLONE_NEWPID | CLONE_NEWCGROUP;

    if (!share_net) {
        flags |= CLONE_NEWNET;
    }

    if (create_fs(tarball_path, parent_pid) != 0) {
        fprintf(stderr, "create fs failed\n");
        exit(1);
    }

    if (mount_overlayfs(parent_pid) == -1) {
        fprintf(stderr, "failed to mount overlayfs\n");
        exit(1);
    }

    int child_args[4] = {shell_mode, ram_limit, cpu_limit, parent_pid};
    pid_t child_pid = clone(child_fn, child_stack + STACK_SIZE, flags | SIGCHLD, child_args);

    if (child_pid == -1) {
        perror("clone");
        exit(1);
    }

    waitpid(child_pid, NULL, 0);

    sleep(2);

    printf("\n");
    printf("cleaning up resources\n");

    cleanup_resources(parent_pid);

    printf("cleaning up overlayfs\n");

    unmount_fs(parent_pid);

    char base_dir[256];
    snprintf(base_dir, sizeof(base_dir), "/tmp/runner-%d", parent_pid);

    if (remove_directory(base_dir) == -1) {
        perror("rmrf base");
        printf("errno %d (%s)\n", errno, strerror(errno));
    }

    printf("overlayfs cleanup done\n");

    return 0;
}
