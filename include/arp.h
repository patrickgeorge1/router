//
// Created by patrickgeorge1 on 3/30/20.
//

#include <stdint.h>
#include <linux/if_ether.h>

#ifndef ROUTER_ARP_H
#define ROUTER_ARP_H

#endif //ROUTER_ARP_H


struct _arp_hdr {
    uint16_t htype;
    uint16_t ptype;
    uint8_t hlen;
    uint8_t plen;
    uint16_t opcode;
    uint8_t sender_mac[6];
    uint8_t sender_ip[4];
    uint8_t target_mac[6];
    uint8_t target_ip[4];
};



void arp_resolve(int sockfd, uint32_t addr, uint8_t *mac);