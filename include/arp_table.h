//
// Created by patrickgeorge1 on 4/1/20.
//

#ifndef ROUTER_ARP_TABLE_H
#define ROUTER_ARP_TABLE_H

#include <sys/param.h>

struct arp_element {
    u_int8_t ip[4];
    u_int8_t mac[6];
};

struct arp_element * create_arp_element (uint8_t * ip, uint8_t * mac) {
    struct arp_element *new_entry = calloc(sizeof(struct arp_element), 1);
    for (int i = 0; i < 4; ++i) {
        new_entry->ip[i] = ip[i];
    }
    for (int i = 0; i < 6; ++i) {
        new_entry->mac[i] = mac[i];
    }
    return new_entry;
}

struct arp_vector {
    struct arp_element * table;
    int size;
};


#endif //ROUTER_ARP_TABLE_H
