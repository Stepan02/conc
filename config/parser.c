#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <stdint.h>
#include <sched.h>
#include "../libs/cJSON.h"

int read_config(config_t *config) {
    char config_path[PATH_MAX * 2];
    char current_working_directory[PATH_MAX];

    if (getcwd(current_working_directory, sizeof(current_working_directory)) == NULL) {
        perror("getcwd");
        return -1;
    }

    snprintf(config_path, sizeof(config_path), "%s/config.json", current_working_directory);

    // clear config_t
    free_config(config);
    memset(config, 0, sizeof(config_t));

    // shell runtime is enabled by default (1 = enabled, 0 = disabled)
    config->shell_mode = 1;

     // open config.json file
    FILE *fp = fopen(config_path, "rb");
    if (!fp) {
        fprintf(stderr, "failed to open config.json\n");
        return -1;
    }

    fseek(fp, 0, SEEK_END);
    const long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // read file content
    char *buffer = malloc(file_size + 1);
    if (!buffer) {
        fclose(fp);
        return -1;
    }

    const size_t read_bytes = fread(buffer, 1, file_size, fp);
    fclose(fp);
    buffer[read_bytes] = '\0'; // add null termination

    // parse config
    cJSON *config_file = cJSON_Parse(buffer);
    free(buffer);

    if (config_file == NULL) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "failed to parse config.json: %s\n", error_ptr);
        }

        return -1;
    }

    // return config object
    const cJSON *shell_mode = cJSON_GetObjectItemCaseSensitive(config_file, "shell");
    if (cJSON_IsBool(shell_mode)) {
        config->shell_mode = cJSON_IsTrue(shell_mode);
    }

    const cJSON *readonly_fs = cJSON_GetObjectItemCaseSensitive(config_file, "readonlyFilesystem");
    if (cJSON_IsBool(readonly_fs)) {
        config->readonly_fs = cJSON_IsTrue(readonly_fs);
    }

    const cJSON *custom_hostname = cJSON_GetObjectItemCaseSensitive(config_file, "hostname");
    if (cJSON_IsString(custom_hostname) && custom_hostname->valuestring) {
        snprintf(config->custom_hostname, sizeof(config->custom_hostname), "%s", custom_hostname->valuestring);
    }

    const cJSON *command = cJSON_GetObjectItem(config_file, "command");
    if (cJSON_IsArray(command)) {
        const int count = cJSON_GetArraySize(command);

        if (count > 0) {
            config->command = calloc(count + 1, sizeof(char *)); // args + null termination
            if (!config->command) {
                perror("failed to allocate command");
                cJSON_Delete(config_file);

                return -1;
            }

            config->command_args_count = 0;

            const cJSON *command_arg = NULL;
            cJSON_ArrayForEach(command_arg, command) {
                if (cJSON_IsString(command_arg) && command_arg->valuestring) {
                    config->command[config->command_args_count++] = strdup(command_arg->valuestring);
                }
            }

            config->command[config->command_args_count] = NULL; // add null termination
        }
    }

    // empty command fallback
    if (config->command == NULL || config->command_args_count == 0) {
        if (config->command != NULL) {
            for (int i = 0; config->command[i] != NULL; i++) {
                free(config->command[i]);
            }

            free(config->command);
            config->command = NULL;
        }

        config->command = calloc(2, sizeof(char *));
        if (!config->command) {
            perror("failed to allocate command");
            cJSON_Delete(config_file);

            return -1;
        }

        config->command[0] = strdup("/bin/sh");
        config->command[1] = NULL;
        config->command_args_count = 1;
    }

    const cJSON *uid = cJSON_GetObjectItemCaseSensitive(config_file, "uid");
    if (cJSON_IsNumber(uid)) {
        config->uid = (uint32_t)uid->valuedouble;
    }

    const cJSON *gid = cJSON_GetObjectItemCaseSensitive(config_file, "gid");
    if (cJSON_IsNumber(gid)) {
        config->gid = (uint32_t)gid->valuedouble;
    }

    // no additional gids by default
    config->additional_gids = NULL;
    config->additional_gids_count = 0;

    const cJSON *additional_gids = cJSON_GetObjectItemCaseSensitive(config_file, "additionalGids");
    if (cJSON_IsArray(additional_gids)) {
       const int count = cJSON_GetArraySize(additional_gids);

        if (count > 0) {
            config->additional_gids = calloc(count + 1, sizeof(gid_t)); // gids + null termination
            if (!config->additional_gids) {
                perror("failed to allocate additional gids");
                cJSON_Delete(config_file);

                return -1;
            }

            config->additional_gids_count = 0;

            const cJSON *additional_gid = NULL;
            cJSON_ArrayForEach(additional_gid, additional_gids) {
                if (cJSON_IsNumber(additional_gid)) {
                    config->additional_gids[config->additional_gids_count++] = additional_gid->valueint;
                }
            }
        }
    }

    const cJSON *ram_limit = cJSON_GetObjectItemCaseSensitive(config_file, "ram");
    if (cJSON_IsNumber(ram_limit)) {
        config->ram_limit = (uint64_t)ram_limit->valuedouble;
    }

    const cJSON *cpu_limit = cJSON_GetObjectItemCaseSensitive(config_file, "cpu");
    if (cJSON_IsNumber(cpu_limit)) {
        config->cpu_limit = (uint64_t)cpu_limit->valuedouble;
    }

    const cJSON *env_variables = cJSON_GetObjectItemCaseSensitive(config_file, "env");
    if (cJSON_IsArray(env_variables)) {
        const int count = cJSON_GetArraySize(env_variables);

        if (count > 0) {
            config->env_variables = calloc(count + 1, sizeof(char *)); // variables + null termination
            if (!config->env_variables) {
                perror("failed to allocate env variables");
                cJSON_Delete(config_file);

                return -1;
            }

            config->env_variables_count = 0;

            const cJSON *variable = NULL;
            cJSON_ArrayForEach(variable, env_variables) {
                if (cJSON_IsString(variable) && variable->valuestring) {
                    config->env_variables[config->env_variables_count++] = strdup(variable->valuestring);
                }
            }

            config->env_variables[config->env_variables_count] = NULL; // add null termination
        }
    }

   const cJSON *cwd = cJSON_GetObjectItemCaseSensitive(config_file, "cwd");
    if (cJSON_IsString(cwd) && cwd->valuestring) {
        snprintf(config->cwd, sizeof(config->cwd), "%s", cwd->valuestring);
    }

    config->pid_limit = 0;

    const cJSON *pids = cJSON_GetObjectItemCaseSensitive(config_file, "pids");
    if (cJSON_IsObject(pids)) {
        const cJSON *limit = cJSON_GetObjectItemCaseSensitive(pids, "limit");
        if (cJSON_IsNumber(limit)) {
            config->pid_limit = (uint64_t) limit->valuedouble;
        }
    }

    const cJSON *namespaces = cJSON_GetObjectItemCaseSensitive(config_file, "namespaces");
    if (cJSON_IsArray(namespaces)) {
        const cJSON *namespace = NULL;

        cJSON_ArrayForEach(namespace, namespaces) {
            if (!cJSON_IsObject(namespace)) {
                continue;
            }

            const cJSON *type = cJSON_GetObjectItemCaseSensitive(namespace, "type");
            if (cJSON_IsString(type) && type->valuestring) {
                const char *value = type->valuestring;

                if (strcmp(value, "pid") == 0) {
                    config->namespaces |= CLONE_NEWPID;
                }

                else if (strcmp(value, "network") == 0) {
                    config->namespaces |= CLONE_NEWNET;
                }

                else if (strcmp(value, "mount") == 0) {
                    config->namespaces |= CLONE_NEWNS;
                }

                else if (strcmp(value, "ipc") == 0) {
                    config->namespaces |= CLONE_NEWIPC;
                }

                else if (strcmp(value, "uts") == 0) {
                    config->namespaces |= CLONE_NEWUTS;
                }

                else if (strcmp(value, "user") == 0) {
                    config->namespaces |= CLONE_NEWUSER;
                }

                else if (strcmp(value, "cgroup") == 0) {
                    config->namespaces |= CLONE_NEWCGROUP;
                }

                else if (strcmp(value, "time") == 0) {
                    config->namespaces |= CLONE_NEWTIME;
                }
            }
        }
    }

    const cJSON *no_new_privileges = cJSON_GetObjectItemCaseSensitive(config_file, "noNewPrivileges");
    if (cJSON_IsBool(no_new_privileges)) {
        config->no_new_privileges = cJSON_IsTrue(no_new_privileges) ? 1 : 0;
    }

    config->console_height = 24;
    config->console_width = 80;

    const cJSON *console_size = cJSON_GetObjectItemCaseSensitive(config_file, "consoleSize");
    if (cJSON_IsObject(console_size)) {
        const cJSON *height = cJSON_GetObjectItemCaseSensitive(console_size, "height");
        const cJSON *width = cJSON_GetObjectItemCaseSensitive(console_size, "width");

        if (cJSON_IsNumber(width)) {
            config->console_width = width->valueint;
        }

        if (cJSON_IsNumber(height)) {
            config->console_height = height->valueint;
        }
    }

    // delete json object
    cJSON_Delete(config_file);

    return 0;
}

void free_config(config_t *config) {
    if (!config) {
        return;
    }

    if (config->env_variables) {
        for (int i = 0; config->env_variables[i] != NULL; i++) {
            free(config->env_variables[i]);
        }

        free(config->env_variables);
        config->env_variables = NULL;
    }

    if (config->command != NULL) {
        for (int i = 0; config->command[i] != NULL; i++) {
            free(config->command[i]);
        }

        free(config->command);
        config->command = NULL;
    }
}
