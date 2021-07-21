
#include <stdio.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include "icmp.h"

void handle_ip(void *packet, ssize_t len)
{
    struct ip *iphdr = packet;
    switch (iphdr->ip_p)
    {
    case IPPROTO_ICMP:
        handle_icmp(packet, len);
    }
}
