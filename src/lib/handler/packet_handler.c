#include <stdio.h>
#include <arpa/inet.h>    // htons
#include <net/ethernet.h> // ether_header, ETHERTYPEs

#include "arp.h"
#include "ip.h"

/// handle ETHER frame
void packet_handler(char *packet, ssize_t len)
{

    struct ether_header *ethframe = (struct ether_header *)packet;
    void *payload = (void *)ethframe + sizeof(struct ether_header);
    ssize_t payload_len = len - sizeof(struct ether_header);

    switch (ntohs(ethframe->ether_type))
    {
    case ETHERTYPE_ARP:
        handle_arp(packet, len);
        break;
    case ETHERTYPE_IP:
        handle_ip(payload, payload_len);
    default:
        break;
    }
}