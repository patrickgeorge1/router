//
// Created by patrickgeorge1 on 4/2/20.
//

#ifndef ROUTER_IP_H
#define ROUTER_IP_H

#include <stdint.h>

struct ip_hdr {
    uint8_t version : 4;
    uint8_t ihl : 4;
    uint8_t tos;
    uint16_t len;
    uint16_t id;
    uint16_t flags : 3;
    uint16_t frag_offset : 13;
    uint8_t ttl;
    uint8_t proto;
    uint16_t csum;
    uint8_t saddr[4];
    uint8_t daddr[4];
} __attribute__((packed));
#endif //ROUTER_IP_H
