#include <stdio.h>
#include "filesystem/fs.h"

int main(int argc , char *argv[]) {
    // no tarball selected
    if (argc < 2) {
        fprintf(stderr, "Usage: ./conc <tarball_path>\n");
        return 1;
    }

    // create overlay filesystem
    overlayfs("/tmp/conc-runtime");

    // unzip root filesystem
    char *tarball_path = argv[1];
    unzipfs(tarball_path, "/tmp/conc-runtime/lowerdir");

    return 0;
}