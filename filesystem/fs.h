#ifndef SANDBOX_FS_H
#define SANDBOX_FS_H

int copy_file(const char *src, const char *container_name);
int create_fs(const char *tarball_path, const char *container_name, int disk_limit);
int remove_directory(const char *path);
int mount_overlayfs(const char *container_name);
int mount_fs();
int unmount_fs(const char *container_name);

extern char merged[256];

#endif //SANDBOX_FS_H
