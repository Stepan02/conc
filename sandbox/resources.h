#ifndef SANDBOX_RESOURCES_H
#define SANDBOX_RESOURCES_H
#include <sched.h>
#include <stdint.h>

int allocate_resources(pid_t child_pid, uint64_t ram_mb, uint64_t cpu_us, uint64_t pid_limit);

#endif //SANDBOX_RESOURCES_H
