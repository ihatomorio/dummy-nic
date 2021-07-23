#include <stdint.h>
#include <stdio.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

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

void print_eth(struct ether_addr *addr)
{
    printf("%02x:%02x:%02x:%02x:%02x:%02x", addr->ether_addr_octet[0], addr->ether_addr_octet[1], addr->ether_addr_octet[2], addr->ether_addr_octet[3], addr->ether_addr_octet[4], addr->ether_addr_octet[5]);
}

void print_inet(struct in_addr *addr)
{
    char addrstr[INET_ADDRSTRLEN] = {0};
    inet_ntop(AF_INET, addr, (char *)&addrstr, INET_ADDRSTRLEN);
    printf("%s", addrstr);
}
