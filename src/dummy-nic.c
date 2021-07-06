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
    int function_result = 0;
    uint8_t *udp_payload = NULL;
    size_t udp_payload_len = 0;
    void *udp_packet = NULL;
    size_t udp_packet_len = 0;
    void *ip_packet = NULL;
    size_t ip_packet_len = 0;
    uint16_t ip_packet_id = 0;
    void *ether_frame = NULL;
    size_t ether_frame_length = 0;
    ssize_t sent_bytes = 0;
    int i;

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

    printf("IF:%s\n", interface_name);

    socket_descriptor = get_raw_socket(interface_name);
    if (socket_descriptor == -1)
    {
        exit_status = 1;
        goto final;
    }

    udp_payload_len = 64 - (sizeof(struct udphdr) + sizeof(struct iphdr) + sizeof(struct ethhdr));
    udp_payload = (uint8_t *)calloc(sizeof(uint8_t), udp_payload_len);
    if (udp_payload == NULL)
    {
        exit_status = 2;
        goto final;
    }

    while(1)
    {
        printf("seq=%d\n", ip_packet_id);

        for(i=0; i<udp_payload_len; i++)
        {
            udp_payload[i] = (i % UINT16_MAX);
        }
        printf("udp_payload_len: %zu\n", udp_payload_len);
        print_hex(udp_payload, udp_payload_len);

        function_result = make_udp_packet(12345, 80, &udp_packet, udp_payload, udp_payload_len);
        if (function_result != 0)
        {
            exit_status = 5;
            goto final;
        }

        udp_packet_len = ntohs(((struct udphdr *)udp_packet)->len);
        
        printf("udp_packet_len: %zu\n", udp_packet_len);
        print_hex(udp_packet, udp_packet_len);

        function_result = make_ip_packet(ip_packet_id, IPPROTO_UDP, "172.24.209.22", "192.168.100.1", &ip_packet, udp_packet, udp_packet_len);
        if (function_result != 0)
        {
            exit_status = 5;
            goto final;
        }

        ip_packet_id++;

        ip_packet_len = ntohs(((struct iphdr *)ip_packet)->tot_len);

        printf("ip_packet_len: %zu\n", ip_packet_len);
        print_hex(ip_packet, ip_packet_len);

        make_ether_frame(&ether_frame, &ether_frame_length, ip_packet, ip_packet_len);

        printf("ether_frame_length: %zu\n", ether_frame_length);
        print_hex(ether_frame, ether_frame_length);

        sent_bytes = send(socket_descriptor, ether_frame, ether_frame_length, 0);
        printf("sent_bytes: %zu\n", sent_bytes);

        SAFE_FREE(udp_packet);
        SAFE_FREE(ip_packet);
        SAFE_FREE(ether_frame);

        printf("\n");
        sleep(1);
    }
    
final:
    SAFE_FREE(udp_payload);
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


int make_udp_packet(int16_t src_port, int16_t dst_port, void **udp_packet, void *udp_payload, size_t udp_payload_len)
{
    int return_code = 0;
    size_t udp_packet_len = sizeof(struct udphdr) + udp_payload_len;
    struct udphdr *udp_header = NULL;

    if(*udp_packet == NULL)
    {
        *udp_packet = calloc(sizeof(int8_t), udp_packet_len);
        if (*udp_packet == NULL)
        {
            return_code = -1;
            goto final;
        }
    }

    memcpy(*udp_packet + sizeof(struct udphdr), udp_payload, udp_payload_len);

    udp_header = (struct udphdr *)*udp_packet;
    udp_header->source = htons(src_port);
    udp_header->dest = htons(dst_port);
    udp_header->len = htons(udp_packet_len);
    udp_header->check = checksum((uint16_t *)*udp_packet, udp_packet_len);
    
final:
    return return_code;
}

int make_ip_packet(uint16_t id, uint8_t protocol, const char *src_ip, const char *dst_ip, void **ip_packet, void *data_buf, size_t data_buf_len)
{
    struct iphdr *ip_header = NULL;
    struct in_addr src_addr;
    struct in_addr dst_addr;
    int convert_result = 1;
    int return_code = 0;
    size_t ip_packet_len = sizeof(struct iphdr) + data_buf_len;

    if(*ip_packet == NULL)
    {
        *ip_packet = calloc(sizeof(int8_t), ip_packet_len);
        if (*ip_packet == NULL)
        {
            return_code = -1;
            goto final;
        }
    }

    ip_header = (struct iphdr *)*ip_packet;

    convert_result = inet_aton(src_ip, &src_addr);
    if (convert_result == 0)
    {
        printf("inet_aton failed.\n");
        return_code = -2;
        goto final;
    }

    convert_result = inet_aton(dst_ip, &dst_addr);
    if (convert_result == 0)
    {
        printf("inet_aton failed.\n");
        return_code = -3;
        goto final;
    }

    ip_header->version = IPVERSION;
    ip_header->ihl = 5;
    ip_header->tos = 0;
    ip_header->tot_len = htons(ip_packet_len);
    ip_header->id = htons(id);
    ip_header->frag_off = htons(0x4000);
    ip_header->ttl = 255;
    ip_header->protocol = protocol;
    ip_header->check = 0;
    ip_header->saddr = src_addr.s_addr;
    ip_header->daddr = dst_addr.s_addr;

    memcpy(*ip_packet, ip_header, sizeof(struct iphdr));
    memcpy(*ip_packet + sizeof(struct iphdr), data_buf, data_buf_len);

    ip_header->check = checksum((uint16_t *)*ip_packet, ip_packet_len);

final:
    return return_code;
}


int make_ether_frame(void **ether_frame, size_t *ether_frame_len, void *data, size_t data_len)
{
    int return_value = 0;
    struct ether_header *ether_frame_header = NULL;

    *ether_frame_len = ETH_HLEN + data_len;
    if (data_len < ETHERMIN)
    {
        *ether_frame_len = ETH_ZLEN;
    }

    if(*ether_frame == NULL)
    {
        *ether_frame = calloc(sizeof(int8_t), *ether_frame_len);
        if (*ether_frame == NULL)
        {
            return_value = -1;
            goto final;
        }
    }

    ether_frame_header = (struct ether_header *)*ether_frame;

    // 00a0 dec0 180c 0800 2720 91f3
    ether_frame_header->ether_dhost[0] = 0x00;
    ether_frame_header->ether_dhost[1] = 0xa0;
    ether_frame_header->ether_dhost[2] = 0xde;
    ether_frame_header->ether_dhost[3] = 0xc0;
    ether_frame_header->ether_dhost[4] = 0x18;
    ether_frame_header->ether_dhost[5] = 0x0c;

    ether_frame_header->ether_shost[0] = 0x00;
    ether_frame_header->ether_shost[1] = 0x15;
    ether_frame_header->ether_shost[2] = 0x5d;
    ether_frame_header->ether_shost[3] = 0xd8;
    ether_frame_header->ether_shost[4] = 0xfa;
    ether_frame_header->ether_shost[5] = 0xd1;

    ether_frame_header->ether_type = htons(ETHERTYPE_IP);

    memcpy(*ether_frame + ETHER_HDR_LEN, data, data_len);

final:
    return return_value;
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
