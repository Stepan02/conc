#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/limits.h>
#include <stdint.h>
#include <sched.h>
#include "../libs/cJSON.h"

int read_config(config_t *config, const char *bundle_path) {
    char config_path[PATH_MAX * 2];

    if (bundle_path) {
        snprintf(config_path, sizeof(config_path), "%s/config.json", bundle_path);
    } else {
        // use current working directory as a bundle path if no bundle path is provided
        char current_working_directory[PATH_MAX];
        getcwd(current_working_directory, sizeof(current_working_directory));

        snprintf(config_path, sizeof(config_path), "%s/config.json", current_working_directory);
    }

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
    const cJSON *process = cJSON_GetObjectItemCaseSensitive(config_file, "process");
    if (cJSON_IsObject(process)) {
        const cJSON *terminal = cJSON_GetObjectItemCaseSensitive(process, "terminal");
        if (cJSON_IsBool(terminal)) {
            config->shell_mode = cJSON_IsTrue(terminal);
        }

        // no additional gids by default
        config->additional_gids = NULL;
        config->additional_gids_count = 0;

        const cJSON *user = cJSON_GetObjectItemCaseSensitive(process, "user");
        if (cJSON_IsObject(user)) {
            const cJSON *uid = cJSON_GetObjectItemCaseSensitive(user, "uid");
            if (cJSON_IsNumber(uid)) {
                config->uid = (uint32_t)uid->valuedouble;
            }

            const cJSON *gid = cJSON_GetObjectItemCaseSensitive(user, "gid");
            if (cJSON_IsNumber(gid)) {
                config->gid = (uint32_t)gid->valuedouble;
            }

            const cJSON *additional_gids = cJSON_GetObjectItemCaseSensitive(user, "additionalGids");
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

            config->umask = -1;

            const cJSON *umask = cJSON_GetObjectItemCaseSensitive(user, "umask");
            if (cJSON_IsNumber(umask)) {
                config->umask = umask->valueint;
            }
        }

        const cJSON *cwd = cJSON_GetObjectItemCaseSensitive(process, "cwd");
        if (cJSON_IsString(cwd) && cwd->valuestring) {
            snprintf(config->cwd, sizeof(config->cwd), "%s", cwd->valuestring);
        }

        const cJSON *no_new_privileges = cJSON_GetObjectItemCaseSensitive(process, "noNewPrivileges");
        if (cJSON_IsBool(no_new_privileges)) {
            config->no_new_privileges = cJSON_IsTrue(no_new_privileges) ? 1 : 0;
        }

        const cJSON *env_variables = cJSON_GetObjectItemCaseSensitive(process, "env");
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

        config->console_height = 24;
        config->console_width = 80;

        const cJSON *console_size = cJSON_GetObjectItemCaseSensitive(process, "consoleSize");
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
    }

    const cJSON *linux_object = cJSON_GetObjectItemCaseSensitive(config_file, "linux");
    if (cJSON_IsObject(linux_object)) {
        const cJSON *resources = cJSON_GetObjectItemCaseSensitive(linux_object, "resources");
        if (cJSON_IsObject(resources)) {
            const cJSON *devices = cJSON_GetObjectItemCaseSensitive(resources, "devices");
            if (cJSON_IsArray(devices)) {
                const int count = cJSON_GetArraySize(devices);
                if (count > 0) {
                    config->devices = malloc(sizeof(device_t) * count);
                    config->devices_count = count;

                    for (int i = 0; i < count; i++) {
                        const cJSON *device = cJSON_GetArrayItem(devices, i);

                        const cJSON *path = cJSON_GetObjectItemCaseSensitive(device, "path");
                        if (cJSON_IsString(path) && path->valuestring) {
                            strncpy(config->devices[i].path, path->valuestring, sizeof(config->devices[i].path) - 1);
                            config->devices[i].path[sizeof(config->devices[i].path) - 1] = '\0';
                        } else {
                            config->devices[i].path[0] = '\0';
                        }

                        const cJSON *allow = cJSON_GetObjectItemCaseSensitive(device, "allow");
                        if (cJSON_IsBool(allow)) {
                            config->devices[i].allow = cJSON_IsTrue(allow);
                        } else {
                            config->devices[i].allow = 0;
                        }

                        const cJSON *access = cJSON_GetObjectItemCaseSensitive(device, "access");
                        if (cJSON_IsString(access) && access->valuestring) {
                            strncpy(config->devices[i].access, access->valuestring, sizeof(config->devices[i].access) - 1);
                            config->devices[i].access[sizeof(config->devices[i].access) - 1] = '\0';
                        } else {
                            config->devices[i].access[0] = '\0';
                        }

                        config->devices[i].uid = 0;
                        config->devices[i].gid = 0;

                        const cJSON *device_uid = cJSON_GetObjectItemCaseSensitive(device, "uid");
                        if (cJSON_IsNumber(device_uid)) {
                            config->devices[i].uid = (uint32_t) device_uid->valuedouble;
                        }

                        const cJSON *device_gid = cJSON_GetObjectItemCaseSensitive(device, "gid");
                        if (cJSON_IsNumber(device_gid)) {
                            config->devices[i].gid = (uint32_t) device_gid->valuedouble;
                        }

                        config->devices[i].file_mode = 0666;

                        const cJSON *file_mode = cJSON_GetObjectItemCaseSensitive(device, "fileMode");
                        if (cJSON_IsNumber(file_mode)) {
                            config->devices[i].file_mode = (uint32_t) file_mode->valuedouble;
                        }
                    }
                }
            }

            const cJSON *memory = cJSON_GetObjectItemCaseSensitive(resources, "memory");
            if (cJSON_IsObject(memory)) {
                const cJSON *limit = cJSON_GetObjectItemCaseSensitive(memory, "limit");
                if (cJSON_IsNumber(limit)) {
                    config->ram_limit = (uint64_t)limit->valuedouble;
                }
            }

            const cJSON *cpu = cJSON_GetObjectItemCaseSensitive(resources, "cpu");
            if (cJSON_IsObject(cpu)) {
                const cJSON *quota = cJSON_GetObjectItemCaseSensitive(cpu, "quota");
                if (cJSON_IsNumber(quota)) {
                    config->cpu_limit = (uint64_t)quota->valuedouble;
                }
            }

            config->pid_limit = 0;

            const cJSON *pids = cJSON_GetObjectItemCaseSensitive(resources, "pids");
            if (cJSON_IsObject(pids)) {
                const cJSON *limit = cJSON_GetObjectItemCaseSensitive(pids, "limit");
                if (cJSON_IsNumber(limit)) {
                    config->pid_limit = (uint64_t) limit->valuedouble;
                }
            }

            config->oom_score_adj = 0;

            const cJSON *oom_score_adj = cJSON_GetObjectItemCaseSensitive(resources, "oomScoreAdj");
            if (cJSON_IsNumber(oom_score_adj)) {
                config->oom_score_adj = oom_score_adj->valueint;
            }
        }

        const cJSON *namespaces = cJSON_GetObjectItemCaseSensitive(linux_object, "namespaces");
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
                    } else if (strcmp(value, "network") == 0) {
                        config->namespaces |= CLONE_NEWNET;
                    } else if (strcmp(value, "mount") == 0) {
                        config->namespaces |= CLONE_NEWNS;
                    } else if (strcmp(value, "ipc") == 0) {
                        config->namespaces |= CLONE_NEWIPC;
                    } else if (strcmp(value, "uts") == 0) {
                        config->namespaces |= CLONE_NEWUTS;
                    } else if (strcmp(value, "user") == 0) {
                        config->namespaces |= CLONE_NEWUSER;
                    } else if (strcmp(value, "cgroup") == 0) {
                        config->namespaces |= CLONE_NEWCGROUP;
                    } else if (strcmp(value, "time") == 0) {
                        config->namespaces |= CLONE_NEWTIME;
                    }
                }
            }
        }

        config->readonly_paths = NULL;

        const cJSON *readonly_paths = cJSON_GetObjectItemCaseSensitive(linux_object, "readonlyPaths");
        if (cJSON_IsArray(readonly_paths)) {
            const int count = cJSON_GetArraySize(readonly_paths);

            if (count > 0) {
                config->readonly_paths = calloc(count + 1, sizeof(char *)); // paths + null termination
                if (!config->readonly_paths) {
                    perror("failed to allocate readonly paths");
                    cJSON_Delete(config_file);

                    return -1;
                }

                config->readonly_paths_count = 0;

                const cJSON *path = NULL;
                cJSON_ArrayForEach(path, readonly_paths) {
                    if (cJSON_IsString(path) && path->valuestring) {
                        config->readonly_paths[config->readonly_paths_count++] = strdup(path->valuestring);
                    }
                }

                config->readonly_paths[config->readonly_paths_count] = NULL; // add null termination
            }
        }

        config->masked_paths = NULL;

        const cJSON *masked_paths = cJSON_GetObjectItemCaseSensitive(linux_object, "maskedPaths");
        if (cJSON_IsArray(masked_paths)) {
            const int count = cJSON_GetArraySize(masked_paths);

            if (count > 0) {
                config->masked_paths = calloc(count + 1, sizeof(char *)); // paths + null termination
                if (!config->masked_paths) {
                    perror("failed to allocate masked paths");
                    cJSON_Delete(config_file);

                    return -1;
                }

                config->masked_paths_count = 0;

                const cJSON *path = NULL;
                cJSON_ArrayForEach(path, masked_paths) {
                    if (cJSON_IsString(path) && path->valuestring) {
                        config->masked_paths[config->masked_paths_count++] = strdup(path->valuestring);
                    }
                }

                config->masked_paths[config->masked_paths_count] = NULL; // add null termination
            }
        }

        const cJSON *sysctl = cJSON_GetObjectItemCaseSensitive(linux_object, "sysctl");
        if (cJSON_IsObject(sysctl)) {
            const int count = cJSON_GetArraySize(sysctl);

            if (count > 0) {
                config->sysctl = calloc(count + 1, sizeof(object_t)); // object + null termination
                if (!config->sysctl) {
                    perror("failed to allocate sysctl");
                    cJSON_Delete(config_file);

                    return -1;
                }

                const cJSON *item = NULL;
                int i = 0;
                cJSON_ArrayForEach(item, sysctl) {
                    if (cJSON_IsString(item) && item->valuestring && item->string) {
                        config->sysctl[i].key = strdup(item->string);
                        config->sysctl[i].value = strdup(item->valuestring);
                        i++;
                    }
                }

                config->sysctl_count = i;
                config->sysctl[config->sysctl_count].key = NULL; // add null termination
            }
        }
    }

    snprintf(config->rootfs_path, sizeof(config->rootfs_path), "rootfs");
    config->readonly_fs = false;

    const cJSON *root = cJSON_GetObjectItemCaseSensitive(config_file, "root");
    if (cJSON_IsObject(root)) {
        const cJSON *path = cJSON_GetObjectItemCaseSensitive(root, "path");

        if (cJSON_IsString(path) && path->valuestring) {
            snprintf(config->rootfs_path, sizeof(config->rootfs_path), "%s", path->valuestring);
        }

        const cJSON *readonly_fs = cJSON_GetObjectItemCaseSensitive(root, "readonly");
        if (cJSON_IsBool(readonly_fs)) {
            config->readonly_fs = cJSON_IsTrue(readonly_fs);
        }
    }

    const cJSON *custom_hostname = cJSON_GetObjectItemCaseSensitive(config_file, "hostname");
    if (cJSON_IsString(custom_hostname) && custom_hostname->valuestring) {
        snprintf(config->custom_hostname, sizeof(config->custom_hostname), "%s", custom_hostname->valuestring);
    }

    const cJSON *args = cJSON_GetObjectItem(process, "args");
    if (cJSON_IsArray(args)) {
        const int count = cJSON_GetArraySize(args);

        if (count > 0) {
            config->command = calloc(count + 1, sizeof(char *)); // args + null termination
            if (!config->command) {
                perror("failed to allocate command");
                cJSON_Delete(config_file);

                return -1;
            }

            config->command_args_count = 0;

            const cJSON *command_arg = NULL;
            cJSON_ArrayForEach(command_arg, args) {
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

    if (config->sysctl != NULL) {
        for (int i = 0; config->sysctl[i].key != NULL; i++) {
            free(config->sysctl[i].key);
            free(config->sysctl[i].value);
        }

        free(config->sysctl);
        config->sysctl = NULL;
    }

    if (config->devices != NULL) {
        free(config->devices);
        config->devices = NULL;
    }

    if (config->additional_gids != NULL) {
        free(config->additional_gids);
        config->additional_gids = NULL;
    }

    if (config->readonly_paths != NULL) {
        for (int i = 0; i < config->readonly_paths_count; i++) {
            free(config->readonly_paths[i]);
        }

        free(config->readonly_paths);
        config->readonly_paths = NULL;
    }

    if (config->masked_paths != NULL) {
        for (int i = 0; i < config->masked_paths_count; i++) {
            free(config->masked_paths[i]);
        }

        free(config->masked_paths);
        config->masked_paths = NULL;
    }
}
