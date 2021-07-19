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

#include "lib/raw_socket.h"

#define USAGE_STR "Usage: %s [-I interface]\n"
#define SAFE_FREE(ptr) { \
                        free(ptr); \
                        ptr = NULL; \
                       }


uint16_t checksum(uint16_t *buf, size_t buflen);
int make_udp_packet(int16_t src_port, int16_t dst_port, void **udp_packet, void *udp_payload, size_t udp_payload_len);
int make_ip_packet(uint16_t id, uint8_t protocol, const char *src_ip, const char *dst_ip, void **ip_packet, void *data_buf, size_t data_buf_len);
int make_ether_frame(void **ether_frame, size_t *ether_frame_len, void *data, size_t data_len);
void print_hex(void *buf, size_t buflen);


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
            exit(EXIT_FAILURE);
        }
    }
    
    if (strlen(interface_name) == 0)
    {
        fprintf(stderr, USAGE_STR, argv[0]);
        exit(EXIT_FAILURE);
    }

    socket_descriptor = get_raw_socket(interface_name);
    if (socket_descriptor == -1)
    {
        fprintf(stderr, "failed at get_raw_socket(%s)\n", interface_name);
        exit_status = 1;
        goto final;
    }

    
final:
    return exit_status;
}


uint16_t checksum(uint16_t *buf, size_t buflen)
{
    unsigned long sum = 0;
    uint16_t checksum;

    while (buflen > 1)
    {
        sum += *buf;
        buf++;
        buflen -= 2;
    }

    if (buflen == 1)
    {
        sum += *(unsigned char *)buf;
    }

    sum = (sum & 0xffff) + (sum >> 16);
    sum = (sum & 0xffff) + (sum >> 16);

    checksum = (uint16_t)~sum;

    return checksum;
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
