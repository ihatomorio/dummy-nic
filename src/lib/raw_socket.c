#include <string.h>         // strcpy
#include <stdio.h>          // printf, strerror
#include <unistd.h>         // close

#include "util.h"

#ifdef __linux
    #include <sys/ioctl.h>      // ioctl, see ioctl_list(2)
    #include <net/if.h>         // struct ifreq
    /// socket, bind
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <net/ethernet.h>   // ETH_P_ALL from PACKET(7)
    #include <arpa/inet.h>      // htons

    #include <errno.h>          // errno

    #include <linux/if_packet.h> // PACKET(7)

#elif defined(__APPLE__)
#include <TargetConditionals.h>
#ifdef TARGET_OS_OSX

    /// bpf
    #include <sys/types.h>
    #include <sys/time.h>
    #include <sys/ioctl.h>
    #include <net/bpf.h>
    /// BIOCSETIF from bpf
    #include <sys/socket.h>
    #include <net/if.h>

    #include <fcntl.h> //open
    #include <stdlib.h> // malloc

    #define BPF_PATH_BUFLEN 11

    static size_t __bpf_buf_zize;

#endif //END TARGET_OS_OSX
#endif //END __linux



int get_raw_socket(const char *device_name)
{
    int socket_descriptor = -1;
    struct ifreq ioctl_request = {0};

    if( device_name == NULL)
    {
        fprintf(stderr, "No device name\n");
        goto final;
    }

    if( strlen(device_name) > IFNAMSIZ )
    {
        fprintf(stderr, "Too long device name\n");
    }
    else if( strlen(device_name) < 1 )
    {
        fprintf(stderr, "Empty device name\n");
    }
    else
    {
        strncpy(ioctl_request.ifr_name, device_name, IFNAMSIZ);
    }

#ifdef __linux
    int syscall_returns = 0;
    struct sockaddr_ll sll;
    int tmp_errno = 0;

    socket_descriptor = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    tmp_errno = errno;

    if (socket_descriptor == -1)
    {
        fprintf(stderr, "system call error: %s\n", strerror(tmp_errno));
        goto final;
    }

    syscall_returns = ioctl(socket_descriptor, SIOCGIFINDEX, &ioctl_request);
    tmp_errno = errno;

    if (syscall_returns == -1)
    {
        fprintf(stderr, "system call error: %s\n", strerror(tmp_errno));
        goto catch;
    }

    sll.sll_family = PF_PACKET;
    sll.sll_protocol = htons(ETH_P_ALL);
    sll.sll_ifindex = ioctl_request.ifr_ifindex;

    syscall_returns = bind(socket_descriptor, (struct sockaddr *)&sll, sizeof(sll));
    tmp_errno = errno;
    
    if (syscall_returns == -1)
    {
        fprintf(stderr, "system call error: %s\n", strerror(tmp_errno));
        goto catch;
    }

#elif defined(__APPLE__)
#include <TargetConditionals.h>
#ifdef TARGET_OS_OSX

    char bpfpath[BPF_PATH_BUFLEN] = {0};
    int i=0;
    u_int bpf_buf_len = 0;
    int syscall_returns = -1;

    /// Try open bpf file
    for( i=0; i<99; i++)
    {
        snprintf(&bpfpath[0], BPF_PATH_BUFLEN, "/dev/bpf%d", i);
        
        socket_descriptor = open(bpfpath, O_RDONLY);
        if( socket_descriptor > 0 )
        {
            fprintf(stdout, "got bpf %s\n", bpfpath);
            break;
        }
    }

    // If failed, none opened.
    if( socket_descriptor == -1)
    {
        fprintf(stderr, "socket error: %d\n", socket_descriptor);
        goto final;
    }

    /// Get buffer len
    syscall_returns = ioctl(socket_descriptor, BIOCGBLEN, &bpf_buf_len);
    if(syscall_returns == -1)
    {
        perror("ioctl(socket_descriptor, BIOCGBLEN, &bpf_buf_len)");
        goto catch;
    }

    __bpf_buf_zize = bpf_buf_len;
    printf("buflen: %u\n", bpf_buf_len);

    /// Set buffer len
    syscall_returns = ioctl(socket_descriptor, BIOCSBLEN, &bpf_buf_len);
    if(syscall_returns == -1)
    {
        perror("ioctl(socket_descriptor, BIOCSBLEN, &bpf_buf_len)");
        goto catch;
    }

    /// bind IF
    syscall_returns = ioctl(socket_descriptor, BIOCSETIF, &ioctl_request);
    if(syscall_returns == -1)
    {
        perror("ioctl(socket_descriptor, BIOCSETIF, &ioctl_request);");
        goto catch;
    }

    /// Enable promisc
    syscall_returns = ioctl(socket_descriptor, BIOCPROMISC, NULL);
    if(syscall_returns == -1)
    {
        perror("ioctl(socket_descriptor, BIOCPROMISC, NULL);");
        goto catch;
    }

#endif //END TARGET_OS_OSX
#endif //END __linux

    goto final;
catch:
    close(socket_descriptor);
    socket_descriptor = -1;
final:
    return socket_descriptor;
}


ssize_t read_raw_packet(int socket_descriptor, char **packet)
{
#if defined(__APPLE__)
#include <TargetConditionals.h>
#ifdef TARGET_OS_OSX
    /// read buffer for some packets
    static char *buf = NULL;
    /// remain bytes in read_buf
    ssize_t read_siz = 0;
    /// head address for read_buf
    static struct bpf_hdr* bpfhdr_ptr = NULL;

    if( buf == NULL)
    {
        buf = (char *)calloc(sizeof(char), __bpf_buf_zize);
    }
    if( buf == NULL )
    {
        perror("calloc buf");
        return -1;
    }

    if( read_siz <= 0 )
    {
        read_siz = read(socket_descriptor, buf, __bpf_buf_zize);
        if( read_siz == -1 )
        {
            perror("read");
            return -1;
        }
        bpfhdr_ptr = (struct bpf_hdr *)buf;
    }
    else
    {
        bpfhdr_ptr = (struct bpf_hdr *)( (char *)bpfhdr_ptr + BPF_WORDALIGN( bpfhdr_ptr->bh_hdrlen + bpfhdr_ptr->bh_caplen) );
        read_siz -= BPF_WORDALIGN( bpfhdr_ptr->bh_hdrlen + bpfhdr_ptr->bh_caplen);
    }

    *packet = (char *)bpfhdr_ptr + bpfhdr_ptr->bh_hdrlen;
    printf("-----------raw_socket \n");
    print_hex(*packet, bpfhdr_ptr->bh_datalen);

#endif
#endif
    return bpfhdr_ptr->bh_datalen;
}
