#ifndef SANDBOX_SECURITY_H
#define SANDBOX_SECURITY_H

int setup_syscall_blacklist(int no_new_privileges);
int syscall_handler(int notify_fd);

#endif //SANDBOX_SECURITY_H
