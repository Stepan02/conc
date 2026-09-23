#include "security.h"
#include <seccomp.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/prctl.h>
#include <sys/ioctl.h>
#include <sys/sysinfo.h>

struct resources {
    uint64_t max;
    uint64_t current;
};

static struct resources read_resources(pid_t pid) {
    struct resources response = {.max = 0, .current = 0};

    char full_path[256];
    snprintf(full_path, 256, "/proc/%d/cgroup", pid);

    FILE *file = fopen(full_path, "r");
    if (!file) {
        return response;
    }

    // parse individual cgroup lines
    char line[256];
    if (fgets(line, sizeof(line), file)) {
        char *cgroup_line = strchr(line, ':');
        if (cgroup_line && cgroup_line[1] == ':') {
            cgroup_line += 2; // skip ::
            cgroup_line[strcspn(cgroup_line, "\r\n")] = 0; // cut new line

            char base_path[256];
            snprintf(base_path, sizeof(base_path), "/sys/fs/cgroup%s", cgroup_line);
            fclose(file);

            char buffer[64];

            // read memory max
            char memory_max_path[320];
            snprintf(memory_max_path, sizeof(memory_max_path), "%s/memory.max", base_path);
            FILE *file_max = fopen(memory_max_path, "r");
            if (file_max) {
                if (fgets(buffer, sizeof(buffer), file_max) && strncmp(buffer, "max", 3) != 0) {
                    response.max = (uint64_t)strtoull(buffer, NULL, 10);
                }
                fclose(file_max);
            }

            // read memory current
            char memory_current_path[320];
            snprintf(memory_current_path, sizeof(memory_current_path), "%s/memory.current", base_path);
            FILE *file_current = fopen(memory_current_path, "r");
            if (file_current) {
                if (fgets(buffer, sizeof(buffer), file_current) && strncmp(buffer, "max", 3) != 0) {
                    response.current = (uint64_t)strtoull(buffer, NULL, 10);
                }
                fclose(file_current);
            }

            return response;
        }
    }

    fclose(file);
    return response;
}

static int memory_write(const pid_t pid, const unsigned long remote_address, const void *buffer, const size_t length) {
    char memory_path[64];
    snprintf(memory_path, sizeof(memory_path), "/proc/%d/mem", pid);

    const int fd = open(memory_path, O_WRONLY);
    if (fd < 0) {
        return -1;
    }

    if (pwrite(fd, buffer, length, (off_t)remote_address) != (ssize_t)length) {
        close(fd);
        return -1;
    }

    close(fd);
    return 0;
}

int setup_syscall_blacklist(void) {
    const scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
    if (!ctx) {
        perror("seccomp_init");
        return -1;
    }

    // blocked syscalls list
    const int syscall_blacklist[] = {
        SCMP_SYS(reboot),
        SCMP_SYS(swapon),
        SCMP_SYS(swapoff),
        SCMP_SYS(kexec_load),
        SCMP_SYS(kexec_file_load),
        SCMP_SYS(init_module),
        SCMP_SYS(finit_module),
        SCMP_SYS(delete_module),
        SCMP_SYS(ptrace),
        SCMP_SYS(process_vm_readv),
        SCMP_SYS(process_vm_writev),
        SCMP_SYS(bpf),
        SCMP_SYS(pivot_root),
        SCMP_SYS(chroot),
        SCMP_SYS(mount),
        SCMP_SYS(umount2),
        SCMP_SYS(ustat),
        SCMP_SYS(sysfs),
        SCMP_SYS(sysinfo),
        SCMP_SYS(acct),
        SCMP_SYS(syslog),
        SCMP_SYS(add_key),
        SCMP_SYS(request_key),
        SCMP_SYS(keyctl),
        SCMP_SYS(adjtimex),
        SCMP_SYS(settimeofday),
        SCMP_SYS(clock_settime),
        SCMP_SYS(io_uring_setup),
        SCMP_SYS(io_uring_enter),
        SCMP_SYS(io_uring_register),
        SCMP_SYS(unshare),
        SCMP_SYS(setns)
    };
    const int num_blocked = sizeof(syscall_blacklist) / sizeof(syscall_blacklist[0]);
    for (int i = 0; i < num_blocked; i++) {
        // add seccomp rule
        if (seccomp_rule_add(ctx, SCMP_ACT_NOTIFY, syscall_blacklist[i], 0) < 0) {
            perror("seccomp_rule_add");
            seccomp_release(ctx);
            return -1;
        }
    }

    // disallow elevating privileges
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0) {
        perror("pr_set_no_new_privs");
        return -1;
    }

    // load seccomp rules
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        return -1;
    }

    // setup listener
    const int notify_fd = seccomp_notify_fd(ctx);
    if (notify_fd < 0) {
        perror("seccomp_notify_fd");
        seccomp_release(ctx);
        return -1;
    }

    seccomp_release(ctx);
    return notify_fd;
}

static struct seccomp_notif_resp syscall_emulator(const struct seccomp_notif *request) {
    printf("syscall %d\n", request->data.nr);

    // setup response
    struct seccomp_notif_resp response = {};
    response.id = request->id;

    // emulate sysinfo syscall
    if (request->data.nr == SCMP_SYS(sysinfo)) {
        const unsigned long remote_address = request->data.args[0];

        // get sysinfo from host
        struct sysinfo info = {};
        if (sysinfo(&info) < 0) {
            response.error = -errno;
            return response;
        }

        // get cgroups info
        struct resources memory = read_resources(request->pid);

        // set cgroup values if set
        if (memory.max > 0) {
            info.mem_unit = 1;
            info.totalram = memory.max;

            // swap is disabled
            info.totalswap = 0;
            info.freeswap = 0;

            // resolve free ram
            if (memory.current < memory.max) {
                info.freeram = memory.max - memory.current;
            } else {
                info.freeram = 0;
            }

            info.bufferram = 0;
            info.sharedram = 0;
        }

        // write sysinfo to child
        if (memory_write(request->pid, remote_address, &info, sizeof(info)) < 0) {
            response.error = -EFAULT;
        } else {
            response.error = 0;
            response.val = 0;
        }

        return response;
    }

    response.error = -EPERM; // permission denied error
    response.val = 0;

    return response;
}

void syscall_handler(const int notify_fd) {
    struct seccomp_notif request = {};
    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &request) == -1) {
        if (errno == ENOENT || errno == EINTR) {
            return;
        }

        perror("ioctl seccomp_notif");
        return;
    }

    printf("intercepted syscall %d (pid %d)\r\n", request.data.nr, request.pid);
    fflush(stdout);

    // get response
    struct seccomp_notif_resp response = {};
    response = syscall_emulator(&request);

    // send the response
    if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &response) == -1) {
        perror("ioctl seccomp_notif_resp");
    }
}
