#ifndef RUNNER_USER_H
#define RUNNER_USER_H
#include <sched.h>
#include "include/types.h"

int map_user(pid_t child_pid, const id_mapping_t *uid_mappings, int uid_mappings_count, const id_mapping_t *gid_mappings, int gid_mappings_count);

#endif //RUNNER_USER_H
