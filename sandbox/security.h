#ifndef SANDBOX_SECURITY_H
#define SANDBOX_SECURITY_H

int setup_syscall_blacklist(void);
void syscall_handler(int notify_fd);

#endif //SANDBOX_SECURITY_H
