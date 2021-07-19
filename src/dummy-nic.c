#include <errno.h>           //errno
#include <stddef.h>          //size_t
#include <stdio.h>           //printf()
#include <stdlib.h>          //calloc(), free()
#include <string.h>          //memcpy()
#include <unistd.h>          //close()
#include <arpa/inet.h>       //inet_aton()
#include <sys/types.h>       //socket(), send()
#include <sys/socket.h>      //socket(), send(), inet_aton()
#include <netinet/in.h>      //inet_aton()
#include <netinet/ip.h>      //iphdr
#include <netinet/udp.h>     //udphdr
#include <net/ethernet.h>
#include <net/if.h>

#ifdef __linux
#elif defined(__APPLE__)
#include <TargetConditionals.h>
#ifdef TARGET_OS_OSX

/// read
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <net/bpf.h>

#endif //END TARGET_OS_OSX
#endif //END __linux

#include "lib/raw_socket.h"
#include "lib/util.h"

#define USAGE_STR "Usage: %s [-I interface]\n"
#define SAFE_FREE(ptr) { \
                        free(ptr); \
                        ptr = NULL; \
                       }


int main(int argc, char *argv[])
{
    int exit_status = EXIT_SUCCESS;
    int option_char;
    char interface_name[IFNAMSIZ] = {0};
    int socket_descriptor = -1;

    while ((option_char = getopt(argc, argv, "I:")) != -1)
    {
        switch (option_char)
        {
        case 'I':
            strncpy(interface_name, optarg, IFNAMSIZ);
            break;
        default: /* '?' */
            fprintf(stderr, USAGE_STR, argv[0]);
            exit_status = EXIT_FAILURE;
            goto final;
        }
    }
    
    if (strlen(interface_name) == 0)
    {
        fprintf(stderr, USAGE_STR, argv[0]);
        exit_status = EXIT_FAILURE;
        goto final;
    }

    socket_descriptor = get_raw_socket(interface_name);
    if (socket_descriptor == -1)
    {
        fprintf(stderr, "failed at get_raw_socket(%s)\n", interface_name);
        exit_status = 1;
        goto final;
    }

    fprintf(stdout, "got socket: %d\n", socket_descriptor);

    char *packet = NULL;
    while(1)
    {
        ssize_t packet_size = read_raw_packet(socket_descriptor, &packet);
        if( packet_size == -1)
        {
            perror("failed at read_raw_packet");
            exit_status = 1;
            goto catch;
        }

        printf("-----------program \n");
        print_hex(packet, packet_size);
    }

catch:
    close(socket_descriptor);
    socket_descriptor = -1;
final:
    return exit_status;
}
