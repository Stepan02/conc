#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

int setup_loopback(void) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("socket");
        return -1;
    }

    struct ifreq ifr = {0};
    strncpy(ifr.ifr_name, "lo", IFNAMSIZ - 1);

    // get interface flags
    if (ioctl(sock, SIOCGIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCGIFFLAGS");
        close(sock);
        return -1;
    }

    ifr.ifr_flags |= (IFF_UP | IFF_RUNNING);

    // write flags
    if (ioctl(sock, SIOCSIFFLAGS, &ifr) < 0) {
        perror("ioctl SIOCSIFFLAGS");
        close(sock);
        return -1;
    }

    close(sock);
    return 0;
}