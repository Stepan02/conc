#include <seccomp.h>
#include <linux/seccomp.h>
#include <stdio.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sched.h>
#include <sys/wait.h>
#include <poll.h>
#include <sys/ioctl.h>

int setup_syscall_blacklist(void) {
    scmp_filter_ctx ctx = seccomp_init(SCMP_ACT_ALLOW);
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
    int num_blocked = sizeof(syscall_blacklist) / sizeof(syscall_blacklist[0]);
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
        perror("PR_SET_NO_NEW_PRIVS");
        return -1;
    }

    // load seccomp rules
    if (seccomp_load(ctx) < 0) {
        perror("seccomp_load");
        seccomp_release(ctx);
        return -1;
    }

    // setup listener
    int notify_fd = seccomp_notify_fd(ctx);
    if (notify_fd < 0) {
        perror("seccomp_notify_fd");
        seccomp_release(ctx);
        return -1;
    }

    seccomp_release(ctx);
    return notify_fd;
}

void syscall_handler(int notify_fd, pid_t child_pid) {
    struct pollfd pfd;
    pfd.fd = notify_fd;
    pfd.events = POLLIN;

    while (1) {
        int status;
        // check whether the child is running
        pid_t running = waitpid(child_pid, &status, WNOHANG);
        if (running > 0) {
            break;
        } else if (running == -1 && errno != ECHILD) {
            perror("syscall_handler waitpid");
            break;
        }

        // wait for notify_fd event
        int poll_ret = poll(&pfd, 1, 100);

        if (poll_ret > 0 && (pfd.revents & POLLIN)) {
            struct seccomp_notif req = {};
            if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_RECV, &req) == -1) {
                if (errno == ENOENT || errno == EINTR) {
                    continue;
                }

                perror("ioctl seccomp_notif");
                break;
            }

            printf("intercepted syscall %d (pid %d)\n", req.data.nr, req.pid);

            // setup response
            struct seccomp_notif_resp response = {};
            response.id = req.id;
            response.error = -EPERM; // permission denied error
            response.val = 0;

            // send the response
            if (ioctl(notify_fd, SECCOMP_IOCTL_NOTIF_SEND, &response) == -1) {
                perror("ioctl seccomp_notif_resp");
                break;
            }
        }
    }
}
