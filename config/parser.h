#ifndef SANDBOX_PARSER_H
#define SANDBOX_PARSER_H
#include <stdbool.h>
#include <stdint.h>

typedef struct {
    bool shell_mode;
    bool share_net;
    bool readonly_fs;
    char custom_hostname[256];
    int uid;
    int gid;
    int ram_limit;
    int cpu_limit;
    char **env_variables;
    int env_variables_count;
} config_t;

int read_config(config_t *config);
void free_config(config_t *config);

#endif //SANDBOX_PARSER_H
