#include <errno.h>           //errno
#include <stddef.h>          //size_t
#include <stdio.h>           //printf()
#include <stdlib.h>          //calloc(), free()
#include <string.h>          //memcpy(), strlen, strncpy
#include <unistd.h>          //close()
#include <arpa/inet.h>       //inet_aton()
#include <net/ethernet.h>    // ether_header
#include <net/if.h>          // IFNAMSIZ
/// ETHERS(3) ether_aton
#include <sys/types.h>
#include <sys/socket.h>
#include <net/ethernet.h>

#ifdef __linux
#include <netinet/ether.h>  // ETHER_ATON
#endif

#include "lib/raw_socket.h"
#include "lib/util.h"
#include "lib/handler/packet_handler.h"
#include "lib/nics.h"

#define USAGE_STR "Usage: %s -I interface [-m macaddr] [-a ipaddr]\n"
#define OPTION_CHAR "I:a:m:"

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
    struct ether_addr *mac = NULL;
    struct in_addr argip = {0};

    vnic_entry = 1;

    vnic = calloc(sizeof(struct nicinfo), vnic_entry);

    while ((option_char = getopt(argc, argv, OPTION_CHAR)) != -1)
    {
        switch (option_char)
        {
        case 'I':
            strncpy(interface_name, optarg, IFNAMSIZ);
            break;
        case 'a':
            if( 0 == inet_aton(optarg, &argip) )
            {
                fprintf(stderr, "ipaddr invalid.\n");
                goto final;
            }
            memcpy(&vnic[0].ipaddr, &argip, sizeof(struct in_addr));
            break;
        case 'm':
            mac = ether_aton(optarg);
            if( mac == NULL )
            {
                fprintf(stderr, "macaddr invalid.\n");
                goto final;
            }
            memcpy(&vnic[0].macaddr, mac, sizeof(struct ether_addr));
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

    raw_sockfd = socket_descriptor;
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

        packet_handler(packet, packet_size);
    }

catch:
    close(socket_descriptor);
    socket_descriptor = -1;
final:
    return exit_status;
}
