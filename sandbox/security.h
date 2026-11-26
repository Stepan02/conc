#pragma once
#include "include/types.h"

int setup_syscall_filter(const char *default_action_name, unsigned int default_errno_return, const object_t *syscalls,
                         int syscalls_count, char **architectures, int architectures_count);
int syscall_handler(int notify_fd);
