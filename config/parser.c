#include "parser.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
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

    const cJSON *share_net = cJSON_GetObjectItemCaseSensitive(config_file, "shareNet");
    if (cJSON_IsBool(share_net)) {
        config->share_net = cJSON_IsTrue(share_net);
    }

    const cJSON *readonly_fs = cJSON_GetObjectItemCaseSensitive(config_file, "readonlyFilesystem");
    if (cJSON_IsBool(readonly_fs)) {
        config->readonly_fs = cJSON_IsTrue(readonly_fs);
    }

    const cJSON *custom_hostname = cJSON_GetObjectItemCaseSensitive(config_file, "hostname");
    if (cJSON_IsString(custom_hostname) && custom_hostname->valuestring) {
        snprintf(config->custom_hostname, sizeof(config->custom_hostname), "%s", custom_hostname->valuestring);
    }

    const cJSON *uid = cJSON_GetObjectItemCaseSensitive(config_file, "uid");
    if (cJSON_IsNumber(uid)) {
        config->uid = (uint32_t)uid->valuedouble;
    }

    const cJSON *gid = cJSON_GetObjectItemCaseSensitive(config_file, "gid");
    if (cJSON_IsNumber(gid)) {
        config->gid = (uint32_t)gid->valuedouble;
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
            config->env_variables = calloc(count, sizeof(char *));
            config->env_variables_count = 0;

            cJSON *variable = NULL;
            cJSON_ArrayForEach(variable, env_variables) {
                if (cJSON_IsString(variable) && variable->valuestring) {
                    config->env_variables[config->env_variables_count++] = strdup(variable->valuestring);
                }
            }
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
        for (size_t i = 0; i < config->env_variables_count; i++) {
            free(config->env_variables[i]);
        }

        free(config->env_variables);
        config->env_variables = NULL;
    }
}
