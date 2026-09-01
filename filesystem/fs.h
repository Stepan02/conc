#ifndef SANDBOX_FS_H
#define SANDBOX_FS_H

int create_fs(const char *tarball_path, int pid);
int remove_directory(const char *path);
int mount_overlayfs(int pid);
int mount_fs();
int unmount_fs(int pid);

extern char merged[256];

#endif //SANDBOX_FS_H
