#include <stdio.h>

#include "arp.h"

/// handle from ETHER frame
void handle_icmp(char *packet, ssize_t len)
{
    printf("ICMP\n");
    // int i;
    // struct ether_header *eth_hdr = (struct ether_header *)packet;
}
