#ifndef RUNNER_IPC_H
#define RUNNER_IPC_H

int send_fd(int sock, int fd);
int recv_fd(int sock);

#endif //RUNNER_IPC_H
