#ifndef SANDBOX_SECURITY_H
#define SANDBOX_SECURITY_H

int setup_syscall_blacklist(void);
void syscall_handler(int notify_fd, pid_t child_pid);

#endif //SANDBOX_SECURITY_H
