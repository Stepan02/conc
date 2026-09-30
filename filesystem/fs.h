#ifndef SANDBOX_FS_H
#define SANDBOX_FS_H
#include <linux/limits.h>

int copy_file(const char *source_path, const char *destination_path);
int remove_directory(const char *path);
int mount_overlayfs(const char *rootfs_path, const char *container_name, int disk_limit);
int unmount_fs(const char *container_name);

extern char merged[PATH_MAX + 32];

#endif //SANDBOX_FS_H
