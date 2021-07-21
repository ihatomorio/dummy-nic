#include <stdio.h>
#include <arpa/inet.h>      // htons
#include <net/ethernet.h>   // ether_header
#include <netinet/ip.h>
#include <netinet/in.h>

#include "handler/arp.h"
#include "handler/icmp.h"

/// handle ETHER frame
void packet_handler(char *packet, ssize_t len)
{
    
    struct ether_header *ethframe = (struct ether_header *)packet;
    struct ip *iphdr = (void *)ethframe + sizeof(struct ether_header);

    switch (ethframe->ether_type)
    {
    case htons(ETHERTYPE_ARP):
        handle_arp(packet, len);
        break;
    case htons(ETHERTYPE_IP):
        switch (iphdr->ip_p)
        {
        case IPPROTO_ICMP:
            handle_icmp(packet, len);
        }
    default:
        break;
    }
}