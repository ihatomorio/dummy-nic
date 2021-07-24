#include <stdio.h>
#include <net/ethernet.h> // ether_header
#include <net/if_arp.h>
#include <arpa/inet.h> //ntohs BYTEORDER
#include <stdbool.h>
#include <string.h>
#include <stdlib.h>

#include "../raw_socket.h"
#include "../util.h"

#include "arp.h"
#include "../nics.h"

/// handle from ETHER frame
void handle_arp(char *packet, ssize_t len)
{
    int i;
    struct ether_header *eth_hdr = (struct ether_header *)packet;
    struct arphdr *arp_hdr = (void *)eth_hdr + sizeof(struct ether_header);

    struct ether_addr *arp_sha = (void *)arp_hdr + sizeof(struct arphdr);
    struct in_addr *arp_spa = (void *)arp_sha + arp_hdr->ar_hln;
    struct ether_addr *arp_tha = (void *)arp_spa + arp_hdr->ar_pln;
    struct in_addr *arp_tpa = (void *)arp_tha + arp_hdr->ar_hln;

    print_arp(packet, len);

    switch (ntohs(arp_hdr->ar_op))
    {
    case ARPOP_REQUEST:
        for (i = 0; i < vnic_entry; i++)
        {
            if (is_same_ip(&vnic[i].ipaddr, arp_tpa))
            {
                reply_arp(&vnic[i].macaddr, &vnic[i].ipaddr, arp_sha, arp_spa);
            }
        }

        break;
    case ARPOP_REPLY:
        //nop
        break;
    }
}

void reply_arp(struct ether_addr *sha, struct in_addr *spa, struct ether_addr *tha, struct in_addr *tpa)
{
    // Make ARP frame length
    ssize_t len = sizeof(struct ether_header) + sizeof(struct arphdr) + 2 * sizeof(struct ether_addr) + 2 * sizeof(struct in_addr);

    // Allocate frame buffer
    void *packet = calloc(len, sizeof(char));
    if (packet == NULL)
    {
        return;
    }

    // Set ether frame header
    struct ether_header *eth_hdr = (struct ether_header *)packet;
    memcpy(eth_hdr->ether_dhost, tha, sizeof(struct ether_addr));
    memcpy(eth_hdr->ether_shost, sha, sizeof(struct ether_addr));
    eth_hdr->ether_type = htons(ETHERTYPE_ARP);

    // Set ARP frame header
    struct arphdr *arp_hdr = (void *)eth_hdr + sizeof(struct ether_header);
    arp_hdr->ar_hrd = htons(ARPHRD_ETHER);
    arp_hdr->ar_pro = htons(ETHERTYPE_IP);
    arp_hdr->ar_hln = sizeof(struct ether_addr);
    arp_hdr->ar_pln = sizeof(struct in_addr);
    arp_hdr->ar_op = htons(ARPOP_REPLY);

    // Make ARP frame payload
    struct ether_addr *arp_sha = (void *)arp_hdr + sizeof(struct arphdr);
    struct in_addr *arp_spa = (void *)arp_sha + arp_hdr->ar_hln;
    struct ether_addr *arp_tha = (void *)arp_spa + arp_hdr->ar_pln;
    struct in_addr *arp_tpa = (void *)arp_tha + arp_hdr->ar_hln;
    memcpy(arp_sha, sha, sizeof(struct ether_addr));
    memcpy(arp_spa, spa, sizeof(struct in_addr));
    memcpy(arp_tha, tha, sizeof(struct ether_addr));
    memcpy(arp_tpa, tpa, sizeof(struct in_addr));

    printf("its me!\n");
    print_arp(packet, len);
    print_hex(packet, len);

    // send ARP frame
    send(raw_sockfd, packet, len, 0);
}

void announce_mac(struct ether_addr *mac, struct in_addr *ip, int count)
{
    // make ARP is-at broadcast reply
    // send to socket fd raw_sockfd
}

inline bool is_same_mac(struct ether_addr *mac1, struct ether_addr *mac2)
{
    return (0 == memcmp((void *)mac1, (void *)mac2, sizeof(struct ether_addr)));
}

inline bool is_same_ip(struct in_addr *ip1, struct in_addr *ip2)
{
    return (0 == memcmp(ip1, ip2, sizeof(struct in_addr)));
}

void print_arp(char *packet, ssize_t len)
{
    struct ether_header *eth_hdr = (struct ether_header *)packet;
    struct arphdr *arp_hdr = (struct arphdr *)(packet + sizeof(struct ether_header));

    struct ether_addr *arp_sha = (void *)arp_hdr + sizeof(struct arphdr);
    struct in_addr *arp_spa = (void *)arp_sha + arp_hdr->ar_hln;
    struct ether_addr *arp_tha = (void *)arp_spa + arp_hdr->ar_pln;
    struct in_addr *arp_tpa = (void *)arp_tha + arp_hdr->ar_hln;

    struct in_addr zero_ip = {0};

    print_eth((struct ether_addr *)eth_hdr->ether_shost);
    printf(" > ");
    print_eth((struct ether_addr *)eth_hdr->ether_dhost);
    printf(", ARP, length %zu: ", len);

    switch (ntohs(arp_hdr->ar_op))
    {
    case ARPOP_REQUEST:
        if (0 == memcmp(arp_spa, &zero_ip, sizeof(struct in_addr)))
        {
            printf("Probe");
        }
        else
        {
            printf("Request");
        }
        printf(" who-has ");
        print_inet(arp_tpa);
        printf(" (");
        print_eth(arp_tha);
        printf(") tell ");
        print_inet(arp_spa);
        printf(" (");
        print_eth(arp_sha);
        printf(") ");
        break;
    case ARPOP_REPLY:
        printf("Reply ");
        print_inet(arp_spa);
        printf(" is-at ");
        print_eth((struct ether_addr *)arp_sha);
        break;
    default:
        printf("Unknown ARPOP: %u", ntohs(arp_hdr->ar_op));
    }
    printf("\n");
}
