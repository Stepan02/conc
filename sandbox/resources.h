#ifndef SANDBOX_RESOURCES_H
#define SANDBOX_RESOURCES_H
#include <sched.h>

void create_resources(pid_t child_pid, int ram_mb, int cpu_us);
void allocate_resources(pid_t cgroup_id);
void cleanup_resources(pid_t child_pid);

#endif //SANDBOX_RESOURCES_H
