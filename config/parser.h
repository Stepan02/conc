#ifndef SANDBOX_PARSER_H
#define SANDBOX_PARSER_H
#include <stdbool.h>
#include <linux/limits.h>

typedef struct {
    bool shell_mode;
    bool readonly_fs;
    char custom_hostname[256];
    int uid;
    int gid;
    int *additional_gids;
    int additional_gids_count;
    int ram_limit;
    int cpu_limit;
    char **env_variables;
    int env_variables_count;
    char **command;
    int command_args_count;
    int namespaces;
    int pid_limit;
    char cwd[PATH_MAX];
    bool no_new_privileges;
    int console_width;
    int console_height;
} config_t;

int read_config(config_t *config);
void free_config(config_t *config);

#endif //SANDBOX_PARSER_H
