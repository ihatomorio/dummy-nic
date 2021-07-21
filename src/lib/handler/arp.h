#ifndef __ARP_H
#define __ARP_H

#include <stdbool.h>
#include <net/ethernet.h>
#include <netinet/in.h>

extern struct nicinfo *vnic;
extern int vnic_entry;

void handle_arp(char *packet, ssize_t len);

void reply_arp(struct ether_addr *arp_sha, struct in_addr *arp_spa, struct ether_addr *arp_tha, struct in_addr *arp_tpa);
void announce_mac(struct ether_addr *mac, struct in_addr *ip, int count);
bool is_same_mac(struct ether_addr *mac1, struct ether_addr *mac2);
bool is_same_ip(struct in_addr *ip1, struct in_addr *ip2);
void print_arp(char *packet, ssize_t len);

#endif
