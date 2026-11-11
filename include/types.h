#ifndef SANDBOX_TYPES_H
#define SANDBOX_TYPES_H
#include <linux/limits.h>

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
    int readonly;
    int bind;
    int nosuid;
    int nodev;
    int noexec;
} mount_t;

#endif //SANDBOX_TYPES_H
