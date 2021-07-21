#include <stdio.h>
#include <arpa/inet.h>      // htons
#include <net/ethernet.h>   // ether_header

#include "handler/arp.h"

/// handle ETHER frame
void packet_handler(char *packet, ssize_t len)
{
    
    struct  ether_header *ethframe = (struct ether_header *)packet;

    switch (ethframe->ether_type)
    {
    case htons(ETHERTYPE_ARP):
        handle_arp(packet, len);
        break;
    
    default:
        break;
    }
}