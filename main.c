#include <elf.h>
#include <sched.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/un.h>
#include <errno.h>
#include <pty.h>
#include <string.h>
#include <termios.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <grp.h>
#include "config/parser.h"
#include "filesystem/fs.h"
#include "sandbox/resources.h"
#include "sandbox/security.h"
#include "sandbox/network.h"
#include "sandbox/user.h"
#include "sandbox/ipc.h"

// global container name variable
static char container_name[64];

// global hostname variable
static char hostname[64];

// global current working directory variable
static char cwd[PATH_MAX] = "/"; // default directory

// global disk_limit variable
static int disk_limit = 1024; // mb

// global files to copy buffers
static char file_sources[10][512];
static int file_count = 0;

// global env variables
static char **env_variables = NULL;
static int env_variables_count = 0;

// global uid and gid variables
static int uid = 0; // default uid
static int gid = 0; // default gid

// global shell mode variable
static int shell_mode = 1; // shell runtime is enabled by default (1 = enabled, 0 = disabled)

// setup child process stack and command variable
#define STACK_SIZE (1024 * 1024)
static char child_stack[STACK_SIZE];
static char **command = NULL;

static int container_runtime(void *arg) {
    const uintptr_t *args = arg;
    const int share_net = (int)args[0];
    const int sync_sock = (int)args[1];
    const int slave_fd = (int)args[2];
    const int readonly_fs = (int)args[3];
    const int no_new_privileges = (int)args[4];
    const int *additional_gids = (const int *)args[5];
    const int additional_gids_count = (int)args[6];

    if (mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL) == -1) {
        perror("mount MS_PRIVATE");
    }

    char sync_pipe;
    if (read(sync_sock, &sync_pipe, 1) != 1) {
        fprintf(stderr, "child_fn sync_pipe");
        _exit(1);
    }

    // resolve rootfs path
    char current_path[PATH_MAX];
    if (getcwd(current_path, sizeof(current_path)) == NULL) {
        fprintf(stderr, "failed to get current working directory\n");
        _exit(1);
    }

    char rootfs_path[PATH_MAX + 64];
    snprintf(rootfs_path, sizeof(rootfs_path), "%s/rootfs", current_path);

    // check rootfs
    if (access(rootfs_path, F_OK) < 0) {
        fprintf(stderr, "rootfs not found in %s\n", rootfs_path);
        _exit(1);
    }

    if (mount_overlayfs(rootfs_path, container_name, disk_limit) == -1) {
        fprintf(stderr, "failed to mount overlayfs\n");
        _exit(1);
    }

    snprintf(merged, sizeof(merged), "/tmp/runner-%s/merged", container_name);

    // copy files if provided
    for (int i = 0; i < file_count; i++) {
        // get filename
        const char *filename = strrchr(file_sources[i], '/');
        if (filename) {
            filename++;
        } else {
            filename = file_sources[i];
        }

        // get target path
        char target_path[PATH_MAX * 2];
        snprintf(target_path, sizeof(target_path), "%s/%s", merged, filename);

        if (copy_file(file_sources[i], target_path) != 0) {
            fprintf(stderr, "copy failed\n");
            _exit(1);
        }
    }

    // check merged mountpoint
    if (mount(merged, merged, NULL, MS_BIND, NULL) == -1) {
        perror("mount bind merged");
        _exit(1);
    }

    // mount procfs
    char path[PATH_MAX + 64];
    snprintf(path, sizeof(path), "%s/proc", merged);
    if (mount("proc", path, "proc", 0, NULL) == -1) {
        perror("mount /proc");
    }

    snprintf(path, sizeof(path), "%s/tmp", merged);
    mkdir(path, 0777);

    // mask fips
    char fips_path[PATH_MAX + 64];
    snprintf(fips_path, sizeof(fips_path), "%s/proc/sys/crypto/fips_enabled", merged);
    if (access(fips_path, F_OK) == 0) {
        const int tmp_fd = open("/tmp/fips_zero", O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (tmp_fd != -1) {
            if (write(tmp_fd, "0\n", 2) != 2) {
                perror("write fips_zero");
            }

            close(tmp_fd);
            mount("/tmp/fips_zero", fips_path, NULL, MS_BIND, NULL);
        }
    }

    // mask sysrq-trigger
    char sysrq_trigger_path[PATH_MAX + 64];
    snprintf(sysrq_trigger_path, sizeof(sysrq_trigger_path), "%s/proc/sysrq-trigger", merged);
    if (mount("/dev/null", sysrq_trigger_path, NULL, MS_BIND, NULL) == -1) {
        perror("mask sysrq-trigger");
    }

    char sys_path[PATH_MAX + 64];
    snprintf(sys_path, sizeof(sys_path), "%s/proc/sys", merged);
    if (mount(sys_path, sys_path, NULL, MS_BIND | MS_REC, NULL) == 0) {
        mount(sys_path, sys_path, NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL);
    }

    snprintf(path, sizeof(path), "%s/dev", merged);
    mkdir(path, 0755);

    // mount devices
    for (int i = 0; i < 5; i++) {
        const char *sys_devs[] = {"/dev/null", "/dev/zero", "/dev/random", "/dev/urandom", "/dev/tty"};
        snprintf(path, sizeof(path), "%s%s", merged, sys_devs[i]);

        const int fd = open(path, O_WRONLY | O_CREAT, 0666);
        if (fd != -1) {
            close(fd);
        }

        if (mount(sys_devs[i], path, NULL, MS_BIND, NULL) == -1) {
            perror(sys_devs[i]);
        }
    }

    snprintf(path, sizeof(path), "%s/dev/bashm", merged);
    mkdir(path, 0777);

    snprintf(path, sizeof(path), "%s/dev/pts", merged);
    mkdir(path, 0755);

    if (mount("devpts", path, "devpts", 0, "newinstance,mode=0620,ptmxmode=0666") == -1) {
        perror("mount devpts");
    }

    /*
    // save old root
    char put_old[256];
    snprintf(put_old, sizeof(put_old), "%s/old_root", merged);
    mkdir(put_old, 0700);
    */

    // change root
    if (chdir(merged) == -1) {
        perror("chdir merged");
        _exit(1);
    }

    if (chroot(merged) == -1) {
        perror("chroot");
        _exit(1);
    }

    if (chdir(cwd) == -1) {
        perror("chdir cwd");
        _exit(1);
    }

    /*
    if (syscall(SYS_pivot_root, merged, put_old) == -1) {
        perror("pivot_root");
        _exit(1);
    }

    if (chdir("/") == -1) {
        perror("chdir");
        _exit(1);
    }

    // detach old root
    if (umount2("/old_root", MNT_DETACH) == -1) {
        perror("umount old_root");
    }

    // remove old root
    if (rmdir("/old_root") == -1) {
        perror("rmdir /old_root");
    }
    */

    unlink("/dev/ptmx");
    if (symlink("/dev/pts/ptmx", "/dev/ptmx") == -1) {
        perror("symlink /dev/ptmx");
    }

    chmod("/dev/ptmx", 0666);
    chmod("/dev/pts", 0755);

    // setup loopback if network is isolated
    if (!share_net) {
        if (setup_loopback() != 0) {
            perror("setup lo");
            _exit(1);
        }
    }

    // set filesystem as read-only if read-only flag is provided
    if (readonly_fs) {
        if (mount(NULL, "/", NULL, MS_BIND | MS_REMOUNT | MS_RDONLY, NULL) == -1) {
            perror("remount read-only rootfs");
        }
    }

    // setup hostname
    if (sethostname(hostname, strlen(hostname)) == -1) {
        perror("hostname");
    }

    // set environment variables
    clearenv();

    setenv("TERM", "xterm-256color", 1);
    setenv("PATH", "/bin:/sbin:/usr/bin:/usr/sbin", 1);

    if (uid == 0) {
        setenv("HOME", "/root", 1);
        setenv("USER", "root", 1);
    } else {
        setenv("HOME", "/", 1);
        setenv("USER", "runner", 1);
    }

    for (int i = 0; i < env_variables_count; i++) {
        putenv(env_variables[i]);
    }

    // init syscall blacklist
    const int notify_fd = setup_syscall_blacklist(no_new_privileges);
    if (notify_fd < 0) {
        perror("syscall blacklist");
        _exit(1);
    }

    if (send_fd(sync_sock, notify_fd) < 0) {
        perror("send_fd");
        _exit(1);
    }

    close(notify_fd);
    close(sync_sock);

    // no shell mode
    if (shell_mode == 0) {
        // disable stdin
        const int null_fd = open("/dev/null", O_RDONLY);
        if (null_fd != -1) {
            dup2(null_fd, STDIN_FILENO);
            close(null_fd);
        }
    } else {
        // shell mode
        dup2(slave_fd, STDIN_FILENO);
        dup2(slave_fd, STDOUT_FILENO);
        dup2(slave_fd, STDERR_FILENO);
        close(slave_fd);

        setsid();
        if (ioctl(STDIN_FILENO, TIOCSCTTY, 0) == -1) {
            perror("ioctl tiocsctty");
        }
    }

    // set groups
    if (setgroups(additional_gids_count, (const gid_t *)additional_gids) < 0) {
        perror("setgroups");
        _exit(1);
    }

    // set uid and gid
    if (uid != 0 || gid != 0) {
        if (setgid(gid) < 0) {
            perror("setgid");
            _exit(1);
        }

        if (setuid(uid) < 0) {
            perror("setuid");
            _exit(1);
        }
    }

    // close descriptors
    syscall(SYS_close_range, 3, ~0U, 0);
    execvp(command[0], command);
    perror("execvp");
    _exit(1);

    return 0;
}

static int create_container(char *argv[]) {
    // default values
    int ram_limit = 256; // mb
    int cpu_limit = 100000; // us
    char custom_hostname[64] = "";
    int readonly_fs = 0; // filesystem is writable by default
    int no_new_privileges = 1; // disallow elevating privileges by default
    int console_height = 24; // default console rows
    int console_width = 80; // default console columns

    // save container name
    snprintf(container_name, sizeof(container_name), "%s", argv[2]);

    // read container config
    config_t config = {0};

    if (read_config(&config) < 0) {
        perror("read config");
        return 1;
    }

    shell_mode = config.shell_mode;
    readonly_fs = config.readonly_fs;

    if (config.cwd[0] != '\0') {
        snprintf(cwd, sizeof(cwd), "%s", config.cwd);
    }

    int share_net;

    if (config.namespaces & CLONE_NEWNET) {
        share_net = 0;
    } else {
        share_net = 1;
    }

    if (config.custom_hostname[0] != '\0') {
        snprintf(custom_hostname, sizeof(custom_hostname), "%s", config.custom_hostname);
    }

    ram_limit = config.ram_limit;
    cpu_limit = config.cpu_limit;

    uid = config.uid;
    gid = config.gid;

    if (config.env_variables_count > 0) {
        env_variables = calloc(config.env_variables_count + 1, sizeof(char *));

        for (int i = 0; i < config.env_variables_count; i++) {
            env_variables[i] = config.env_variables[i];
        }
    }

    command = config.command;
    no_new_privileges = config.no_new_privileges;

    // prepare container base directory
    char base_dir[256];
    snprintf(base_dir, sizeof(base_dir), "/tmp/runner-%s", container_name);

    if (mkdir(base_dir, 0755) < 0) {
        perror("failed to create base directory");
        return 1;
    }

    // write shell mode to a file
    char shell_mode_path[512];
    snprintf(shell_mode_path, sizeof(shell_mode_path), "%s/shell-mode", base_dir);

    const int shell_mode_fd = open(shell_mode_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (shell_mode_fd != -1) {
        const char *shell_mode_value = shell_mode ? "1\n" : "0\n";

        if (write(shell_mode_fd, shell_mode_value, 2) < 0) {
            perror("failed to set shell mode");
            close(shell_mode_fd);
            return 1;
        }

        close(shell_mode_fd);
    }

    // write console size to a file
    console_height = config.console_height;
    console_width = config.console_width;

    char console_size_path[512];
    snprintf(console_size_path, sizeof(console_size_path), "%s/console-size", base_dir);

    const int console_size_fd = open(console_size_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (console_size_fd != -1) {
        char console_size_value[64];
        const int console_size = snprintf(console_size_value, sizeof(console_size_value), "%d %d\n", console_height, console_width);

        if (write(console_size_fd, console_size_value, console_size) < 0) {
            perror("failed to set console size");
            close(console_size_fd);
            return 1;
        }

        close(console_size_fd);
    }

    // create sync socket
    char socket_path[512];
    snprintf(socket_path, sizeof(socket_path), "%s/sync.sock", base_dir);

    const int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("failed to create socket");
        return 1;
    }

    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, socket_path, sizeof(address.sun_path) - 1);
    address.sun_path[sizeof(address.sun_path) - 1] = '\0';

    unlink(socket_path);

    if (bind(socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("failed to bind socket");
        close(socket_fd);
        return 1;
    }

    if (listen(socket_fd, 1) < 0) {
        perror("failed to listen socket");
        close(socket_fd);
        return 1;
    }

    // fork supervisor
    const pid_t supervisor_pid = fork();
    if (supervisor_pid < 0) {
        perror("failed to fork supervisor");
        close(socket_fd);
        free(env_variables);
        return 1;
    }

    if (supervisor_pid > 0) {
        // save supervisor pid
        char supervisor_pid_path[512];
        snprintf(supervisor_pid_path, sizeof(supervisor_pid_path), "%s/supervisor.pid", base_dir);
        FILE *f_pid = fopen(supervisor_pid_path, "w");

        if (f_pid) {
            fprintf(f_pid, "%d\n", supervisor_pid);
            fclose(f_pid);
        }

        printf("%s\n", container_name);
        close(socket_fd);
        free(env_variables);
        free_config(&config);
        return 0;
    }

    // disconnect from shell
    setsid();

    // wait for container start
    const int start_fd = accept(socket_fd, NULL, NULL);
    if (start_fd < 0) {
        perror("failed to accept connection");
        close(socket_fd);
        _exit(1);
    }

    close(socket_fd);

    // set hostname
    if (strlen(custom_hostname) > 0) {
        snprintf(hostname, sizeof(hostname), "%s", custom_hostname);
    } else {
        snprintf(hostname, sizeof(hostname), "%s", container_name);
    }

    // prepare pty
    int master_fd = -1;
    int slave_fd = -1;
    if (shell_mode) {
        if (openpty(&master_fd, &slave_fd, NULL, NULL, NULL) < 0) {
            perror("openpty");
            exit(1);
        }
    }

    int sync_sockets[2];
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, sync_sockets) < 0) {
        perror("socketpair");
        exit(1);
    }

    const uintptr_t additional_gids = (uintptr_t)config.additional_gids;
    const int additional_gids_count = config.additional_gids_count;

    // clone child
    uintptr_t child_args[7] = {share_net, sync_sockets[1], slave_fd, readonly_fs, no_new_privileges, additional_gids, additional_gids_count};
    const pid_t child_pid = clone(container_runtime, child_stack + STACK_SIZE, config.namespaces | SIGCHLD, child_args);

    if (child_pid == -1) {
        perror("clone");
        exit(1);
    }

    close(sync_sockets[1]);

    // save container pid
    char container_pid_path[512];
    snprintf(container_pid_path, sizeof(container_pid_path), "%s/container.pid", base_dir);
    FILE *f_pid = fopen(container_pid_path, "w");

    if (f_pid) {
        fprintf(f_pid, "%d\n", child_pid);
        fclose(f_pid);
    }

    // map namespace
    if (config.namespaces & CLONE_NEWUSER) {
        if (map_user(child_pid) != 0) {
            perror("map_user");
            close(sync_sockets[0]);
            exit(1);
        }
    }

    // create and assign cgroup
    if (allocate_resources(child_pid, ram_limit, cpu_limit, config.pid_limit) < 0) {
        fprintf(stderr, "allocate_resources\n");

        // kill child
        kill(child_pid, SIGKILL);
        waitpid(child_pid, NULL, 0);

        close(sync_sockets[0]);
        close(start_fd);

        exit(1);
    }

    if (write(sync_sockets[0], "1", 1) != 1) {
        perror("write sync_sockets");
        exit(1);
    }

    // listen to child notifications for syscalls
    const int notify_fd = recv_fd(sync_sockets[0]);
    close(sync_sockets[0]);

    if (notify_fd < 0) {
        fprintf(stderr, "receive notify_fd\n");

        int status;
        waitpid(child_pid, &status, 0);
        close(start_fd);

        exit(1);
    }

    if (slave_fd != -1) {
        close(slave_fd);
    }

    // send fds to container run process
    if (shell_mode) {
        if (send_fd(start_fd, master_fd) < 0) {
            perror("send master_fd");
        }
    }
    if (send_fd(start_fd, notify_fd) < 0) {
        perror("send notify_fd");
    }

    if (master_fd != -1) {
        close(master_fd);
    }

    close(notify_fd);

    // wait for container exit
    int status;
    waitpid(child_pid, &status, 0);

    // save container exit code
    int exit_code = 0;
    if (WIFEXITED(status)) {
        exit_code = WEXITSTATUS(status);
    } else if (WIFSIGNALED(status)) {
        exit_code = 128 + WTERMSIG(status);
    }

    char exit_code_path[512];
    snprintf(exit_code_path, sizeof(exit_code_path), "%s/exit-code", base_dir);
    FILE *f_exit_code = fopen(exit_code_path, "w");
    if (f_exit_code) {
        fprintf(f_exit_code, "%d\n", exit_code);
        fclose(f_exit_code);
    }

    // delete container.pid file
    unlink(container_pid_path);

    // clear environment variables and config
    free(env_variables);
    free_config(&config);

    fflush(stdout);

    close(start_fd);

    return 0;
}

static int start_container() {
    // connect to container sync socket
    char socket_path[512];
    snprintf(socket_path, sizeof(socket_path), "/tmp/runner-%s/sync.sock", container_name);

    const int socket_fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (socket_fd < 0) {
        perror("failed to create socket");
        return -1;
    }

    struct sockaddr_un address = {0};
    address.sun_family = AF_UNIX;
    strncpy(address.sun_path, socket_path, sizeof(address.sun_path) - 1);
    address.sun_path[sizeof(address.sun_path) - 1] = '\0';

    if (connect(socket_fd, (struct sockaddr *)&address, sizeof(address)) < 0) {
        perror("failed to connect socket");
        close(socket_fd);
        return -1;
    }

    // send start byte to supervisor
    const char buffer = '1';
    if (write(socket_fd, &buffer, sizeof(buffer)) < 0) {
        perror("failed to send start byte");
    }

    // load shell mode from shell-mode file
    char shell_mode_path[512];
    snprintf(shell_mode_path, sizeof(shell_mode_path), "/tmp/runner-%s/shell-mode", container_name);

    const int shell_mode_fd = open(shell_mode_path, O_RDONLY);
    if (shell_mode_fd != -1) {
        char shell_mode_value;
        if (read(shell_mode_fd, &shell_mode_value, sizeof(shell_mode_value)) == 1) {
            shell_mode = shell_mode_value == '1';
        }
        close(shell_mode_fd);
    }

    // load console width and height from console-size file
    char console_size_path[512];
    snprintf(console_size_path, sizeof(console_size_path), "/tmp/runner-%s/console-size", container_name);

    int console_height = 0;
    int console_width = 0;

    const int console_size_fd = open(console_size_path, O_RDONLY);
    if (console_size_fd != -1) {
        char console_size_value[64];
        const ssize_t value = read(console_size_fd, console_size_value, sizeof(console_size_value) - 1);

        if (value > 0) {
            console_size_value[value] = '\0'; // add null termination

            char *endptr = NULL;
            errno = 0;

            const long rows = strtol(console_size_value, &endptr, 10);
            if (errno == 0 && endptr != console_size_value) {
                const long columns = strtol(endptr, NULL, 10);

                if (errno == 0 && rows > 0 && columns > 0 && rows <= 65535 && columns <= 65535) {
                    console_height = (int)rows;
                    console_width = (int)columns;
                }
            }
        }

        close(console_size_fd);
    }

    // receive fds from supervisor
    int master_fd = -1;
    if (shell_mode) {
        master_fd = recv_fd(socket_fd);
    }
    const int notify_fd = recv_fd(socket_fd);

    if ((shell_mode && master_fd < 0) || notify_fd < 0) {
        perror("failed to receive fds from supervisor");
        return -1;
    }

    // start tty
    struct termios orig_termios, raw;
    const int is_tty = isatty(STDIN_FILENO);

    if (is_tty) {
        tcgetattr(STDIN_FILENO, &orig_termios);

        if (shell_mode) {
            raw = orig_termios;
            cfmakeraw(&raw);
            tcsetattr(STDIN_FILENO, TCSANOW, &raw);
        }
    }

    fd_set fds;
    char buf[256];
    int max_fd = notify_fd;
    ssize_t n;

    if (shell_mode && master_fd != -1) {
        if (master_fd > max_fd) {
            max_fd = master_fd;
        }

        if (STDIN_FILENO > max_fd) {
            max_fd = STDIN_FILENO;
        }

        // set console size
        if (console_height > 0 && console_width > 0) {
            struct winsize ws = {
                .ws_row = console_height,
                .ws_col = console_width,
            };

            if (ioctl(master_fd, TIOCSWINSZ, &ws) == -1) {
                perror("failed to set console size");
            }
        }
    }

    while (1) {
        FD_ZERO(&fds);

        // monitor input and output in shell mode
        if (shell_mode && master_fd != -1) {
            FD_SET(STDIN_FILENO, &fds);
            FD_SET(master_fd, &fds);
        }

        // monitor syscalls
        FD_SET(notify_fd, &fds);

        // pty loop
        const int sel_ret = select(max_fd + 1, &fds, NULL, NULL, NULL);
        if (sel_ret == -1) {
            if (errno == EINTR) {
                continue;
            }

            perror("select");
            break;
        }

        // continue to another iteration after timeout
        if (sel_ret == 0) {
            continue;
        }

        if (shell_mode) {
            // direct input to child
            if (master_fd != -1 && FD_ISSET(STDIN_FILENO, &fds)) {
                n = read(STDIN_FILENO, buf, sizeof(buf));
                if (n <= 0) {
                    break;
                }

                if (write(master_fd, buf, n) != n) {
                    break;
                }
            }

            // direct child output to pty
            if (master_fd != -1 && FD_ISSET(master_fd, &fds)) {
                n = read(master_fd, buf, sizeof(buf));
                if (n <= 0) {
                    break;
                }

                if (write(STDOUT_FILENO, buf, n) != n) {
                    break;
                }
            }
        }

        // intercept syscall notifications
        if (FD_ISSET(notify_fd, &fds)) {
            if (syscall_handler(notify_fd) < 0) {
                break;
            }
        }
    }

    if (is_tty) {
        tcsetattr(STDIN_FILENO, TCSANOW, &orig_termios);
    }

    if (master_fd != -1) {
        close(master_fd);
    }

    char sync;
    while (read(socket_fd, &sync, 1) > 0) {}
    close(socket_fd);
    close(notify_fd);

    return 0;
}

static int kill_container(const int signal_number) {
    // get container pid
    char container_pid_path[512];
    snprintf(container_pid_path, sizeof(container_pid_path), "/tmp/runner-%s/container.pid", container_name);

    const int fd = open(container_pid_path, O_RDONLY);
    if (fd < 0) {
        perror("container is not running");
        return 1;
    }

    char pid_buffer[32] = {0};
    const ssize_t bytes = read(fd, pid_buffer, sizeof(pid_buffer) - 1);
    close(fd);

    if (bytes <= 0) {
        fprintf(stderr, "read container pid\n");
        return 1;
    }

    const pid_t pid = (pid_t) strtol(pid_buffer, NULL, 10);

    // send signal
    if (kill(pid, signal_number) < 0) {
        perror("send signal");
        return 1;
    }

    return 0;
}

static int delete_container() {
    // check whether the container exists
    char container_directory[512];
    snprintf(container_directory, sizeof(container_directory), "/tmp/runner-%s", container_name);

    if (access(container_directory, F_OK) < 0) {
        fprintf(stderr, "container does not exist\n");
        return 1;
    }

    // check whether the container is running
    char container_pid_path[1024];
    snprintf(container_pid_path, sizeof(container_pid_path), "%s/container.pid", container_directory);

    if (access(container_pid_path, F_OK) == 0) {
        fprintf(stderr, "container is running\n");
        return 1;
    }

    // kill supervisor process
    char supervisor_pid_path[1024];
    snprintf(supervisor_pid_path, sizeof(supervisor_pid_path), "%s/supervisor.pid", container_directory);

    const int fd = open(supervisor_pid_path, O_RDONLY);

    if (fd >= 0) {
        char pid_buffer[32] = {0};
        const ssize_t bytes = read(fd, pid_buffer, sizeof(pid_buffer) - 1);
        close(fd);

        if (bytes <= 0) {
            fprintf(stderr, "read supervisor pid\n");
            return 1;
        }

        const pid_t pid = (pid_t) strtol(pid_buffer, NULL, 10);
        kill(pid, SIGKILL);
    }

    // remove container directory
    if (remove_directory(container_directory) < 0) {
        perror("remove container directory");
        return 1;
    }

    return 0;
}

int main(const int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "please specify a command\n");
        return 1;
    }

    // create command
    if (strcmp(argv[1], "create") == 0) {
        if (argc < 3) {
            fprintf(stderr, "missing container name\n");
            return 1;
        }

        return create_container(argv);
    }

    // start command
    if (strcmp(argv[1], "start") == 0) {
        if (argc < 3) {
            fprintf(stderr, "missing container name\n");
            return 1;
        }

        snprintf(container_name, sizeof(container_name), "%s", argv[2]);
        return start_container();
    }

    // kill command
    if (strcmp(argv[1], "kill") == 0) {
        if (argc < 3) {
            fprintf(stderr, "missing container name\n");
            return 1;
        }

        snprintf(container_name, sizeof(container_name), "%s", argv[2]);

        int signal_number = 15; // default sigterm
        if (argc > 3) {
            signal_number = (int)strtol(argv[3], NULL, 10);
        }

        return kill_container(signal_number);
    }

    // delete command
    if (strcmp(argv[1], "delete") == 0) {
        if (argc < 3) {
            fprintf(stderr, "missing container name\n");
            return 1;
        }

        snprintf(container_name, sizeof(container_name), "%s", argv[2]);

        return delete_container();
    }

    fprintf(stderr, "unknown command %s\n", argv[1]);
    return 1;
}
