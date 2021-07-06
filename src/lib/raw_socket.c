#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <string.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/ethernet.h>

int get_raw_socket(const char *device_name)
{
    int socket_descriptor = -1;
    struct ifreq ioctl_request;
    int syscall_returns = 0;
    struct sockaddr_ll sll;
    int tmp_errno = 0;

    socket_descriptor = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    tmp_errno = errno;

    if (socket_descriptor == -1)
    {
        printf("system call error: %s\n", strerror(tmp_errno));
        goto final;
    }

    strncpy(ioctl_request.ifr_name, device_name, sizeof(ioctl_request.ifr_name) - 1);

    syscall_returns = ioctl(socket_descriptor, SIOCGIFINDEX, &ioctl_request);
    tmp_errno = errno;

    if (syscall_returns == -1)
    {
        printf("system call error: %s\n", strerror(tmp_errno));
        close(socket_descriptor);
        socket_descriptor = -1;
        goto final;
    }

    sll.sll_family = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ioctl_request.ifr_ifindex;

    syscall_returns = bind(socket_descriptor, (struct sockaddr *)&sll, sizeof(sll));
    tmp_errno = errno;
    
    if (syscall_returns == -1)
    {
        printf("system call error: %s\n", strerror(tmp_errno));
        close(socket_descriptor);
        socket_descriptor = -1;
        goto final;
    }

final:
    return socket_descriptor;
}
