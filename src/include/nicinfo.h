#ifndef __NICINFO_H
#define __NICINFO_H

#include <net/ethernet.h> // ether_addr
#include <netinet/in.h>   // in_addr

typedef enum NICINFO_ST
{
    NICST_DOWN = 0,
    NICST_DHCP_DISCOVER, //sent offering IP request
    NICST_DHCP_OFFER,    //recv IP offer
    NICST_DHCP_REQUEST,  //sent using offering IP
    NICST_DHCP_ACK,      //recv using IP
    NICST_PROBE,         //ARP proving
    NICST_UP,            //NIC is UP
} nicstatus;

struct nicinfo
{
    struct ether_addr macaddr; //MAC address
    struct in_addr ipaddr;     //IP address
    nicstatus status;          //NIC status
};

#endif // END __NICINFO_H
