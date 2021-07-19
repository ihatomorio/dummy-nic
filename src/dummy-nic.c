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

/// read
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <net/bpf.h>

#include "lib/raw_socket.h"

#define USAGE_STR "Usage: %s [-I interface]\n"
#define SAFE_FREE(ptr) { \
                        free(ptr); \
                        ptr = NULL; \
                       }


void print_hex(void *buf, size_t buflen)
{
    uint8_t *poiner = (uint8_t *)buf;
    size_t offset = 0;

    for (offset = 0; offset < buflen; offset++)
    {
        printf("%02x", (uint8_t)*poiner);
        poiner++;

        if (offset % 16 == 15)
        {
            printf("\n");
            continue;
        }

        if (offset % 2 == 1)
        {
            printf(" ");
        }
    }

    printf("\n");
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

#if defined(__APPLE__)
#include <TargetConditionals.h>
#ifdef TARGET_OS_OSX
    char buf[4096] = {0};
    struct bpf_hdr* bpfhdr_ptr = NULL;
    char *packet = NULL;
    while(1)
    {
        ssize_t read_siz = 0;
        if( read_siz <= 0 )
        {
            read_siz = read(socket_descriptor, &buf, 4096);
            if( read_siz == -1 )
            {
                perror("read");
                exit_status = 1;
                goto catch;
            }
            bpfhdr_ptr = (struct bpf_hdr *)&buf[0];
        }
        else
        {
            bpfhdr_ptr = (struct bpf_hdr *)( (char *)bpfhdr_ptr + BPF_WORDALIGN( bpfhdr_ptr->bh_hdrlen + bpfhdr_ptr->bh_caplen) );
            read_siz -= BPF_WORDALIGN( bpfhdr_ptr->bh_hdrlen + bpfhdr_ptr->bh_caplen);
        }

        packet = (char *)bpfhdr_ptr + bpfhdr_ptr->bh_hdrlen;
        
        printf("-----------\n");
        print_hex(packet, bpfhdr_ptr->bh_datalen );
    }
#endif
#elif defined __linux
#endif

catch:
    close(socket_descriptor);
final:
    return exit_status;
}
