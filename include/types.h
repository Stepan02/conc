#ifndef SANDBOX_TYPES_H
#define SANDBOX_TYPES_H

typedef struct {
    char *key;
    char *value;
} object_t;

typedef struct {
    int allow;
    char access[8];
    char path[256];
} device_t;

#endif //SANDBOX_TYPES_H
