#ifndef __UTIL_H
#define __UTIL_H

#include <net/ethernet.h>
#include <arpa/inet.h>

void print_hex(void *buf, size_t buflen);
void print_eth(struct ether_addr *addr);
void print_inet(struct in_addr *addr);

#endif
