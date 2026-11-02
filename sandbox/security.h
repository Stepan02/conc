#ifndef SANDBOX_SECURITY_H
#define SANDBOX_SECURITY_H
#include "include/types.h"

int setup_syscall_filter(const char *default_action_name, const object_t *syscalls, int syscalls_count, int no_new_privileges);
int syscall_handler(int notify_fd);

#endif //SANDBOX_SECURITY_H
