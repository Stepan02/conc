#include "hook.h"
#include <sched.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/wait.h>
#include "include/types.h"

int run_hook(const hook_t *hook) {
    if (!hook || !hook->path) {
        return 0;
    }

    // fork hook
    const pid_t pid = fork();
    if (pid < 0) {
        perror("fork hook");
        return -1;
    }

    // execute hook
    if (pid == 0) {
        execvp(hook->path, hook->args);
        perror("execvp hook");
        _exit(1);
    }

    // wait for hook finish
    int status;
    waitpid(pid, &status, 0);

    // return exit code
    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return 0;
    }

    fprintf(stderr, "hook %s\n", hook->path);
    return -1;
}
