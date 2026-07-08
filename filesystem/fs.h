#ifndef FILESYSTEM_H
#define FILESYSTEM_H

int unzipfs(const char * path, const char * dest);
int overlayfs(char * path);

#endif