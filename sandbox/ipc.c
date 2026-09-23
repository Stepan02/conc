#include "ipc.h"
#include <sys/socket.h>
#include <sys/uio.h>

int send_fd(const int sock, const int fd) {
    char buffer[1] = {0};
    struct iovec iov = {.iov_base = buffer, .iov_len = sizeof(buffer)};

    char cmsg_buffer[CMSG_SPACE(sizeof(int))];
    const struct msghdr message = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buffer,
        .msg_controllen = sizeof(cmsg_buffer)
    };

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    if (!cmsg) {
        return -1;
    }

    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int));
    *(int *)CMSG_DATA(cmsg) = fd;

    if (sendmsg(sock, &message, 0) < 0) {
        return -1;
    }

    return 0;
}

int recv_fd(const int sock) {
    char buffer[1];
    struct iovec iov = {.iov_base = buffer, .iov_len = sizeof(buffer)};

    char cmsg_buffer[CMSG_SPACE(sizeof(int))];
    struct msghdr message = {
        .msg_iov = &iov,
        .msg_iovlen = 1,
        .msg_control = cmsg_buffer,
        .msg_controllen = sizeof(cmsg_buffer)
    };

    if (recvmsg(sock, &message, 0) <= 0) {
        return -1;
    }

    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&message);
    if (!cmsg || cmsg->cmsg_type != SCM_RIGHTS) {
        return -1;
    }

    return *(int *)CMSG_DATA(cmsg);
}
