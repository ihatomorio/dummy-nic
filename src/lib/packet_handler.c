#include <stdio.h>
#include <arpa/inet.h>      // htons
#include <net/ethernet.h>   // ether_header

void packet_handler(char *packet, ssize_t len)
{
    
    struct  ether_header *ethframe = (struct ether_header *)packet;

    switch (ethframe->ether_type)
    {
    case htons(ETHERTYPE_ARP):
        printf("length:%zu \n", len);
        break;
    
    default:
        break;
    }
}