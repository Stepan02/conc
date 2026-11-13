#ifndef SANDBOX_TYPES_H
#define SANDBOX_TYPES_H
#include <linux/limits.h>
#include <stdint.h>

typedef struct {
    char *key;
    char *value;
} object_t;

typedef struct {
    int allow;
    char access[8];
    char path[256];
    int uid;
    int gid;
    int file_mode;
} device_t;

typedef struct {
    char source[PATH_MAX];
    char destination[PATH_MAX];
    char type[32];
    int readonly;
    int bind;
    int nosuid;
    int nodev;
    int noexec;
} mount_t;

typedef struct {
    uint32_t container_id;
    uint32_t host_id;
    uint32_t size;
} id_mapping_t;

#endif //SANDBOX_TYPES_H
