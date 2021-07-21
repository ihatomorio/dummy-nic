#include <stdio.h>

/// handle from ETHER frame
void handle_icmp(char *packet, ssize_t len)
{
    printf("ICMP\n");
}
