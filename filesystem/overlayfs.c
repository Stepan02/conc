#include <stdio.h>
#include <unistd.h>
#include <sys/stat.h>

void overlayfs(const char * path) {
    // go to the destination directory
    if (chdir(path) != 0) {
        printf("Creating the destination directory\n");

        if (mkdir(path, 0755) != 0) {
            perror("Error creating the destination directory");
            return;
        }

        if (chdir(path) != 0) {
            perror("Cannot change directory to destination");
            return;
        }
    }

    // create overlay structure
    printf("Creating overlay filesystem\n");

    if (mkdir("lowerdir", 0755) != 0) {
        perror("Error creating the lower overlay directory");
        return;
    }

    if (mkdir("upper", 0755) != 0) {
        perror("Error creating the upper overlay directory");
        return;
    }


    if (mkdir("workdir", 0755) != 0) {
        perror("Error creating the work overlay directory");
        return;
    }

    if (mkdir("mergeddir", 0755) != 0) {
        perror("Error creating the merged overlay directory");
        return;
    }

    printf("Overlay filesystem created\n");
}
