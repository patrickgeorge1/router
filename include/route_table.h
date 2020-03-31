//
// Created by patrickgeorge1 on 3/31/20.
//

#ifndef ROUTER_ROUTE_TABLE_H
#define ROUTER_ROUTE_TABLE_H

#include <stdint.h>

struct route_element {
    int interface;
    u_int32_t mask;
    u_int32_t next_hop;
    u_int32_t prefix;

};

struct route_element* crete_route_element(u_int32_t p, u_int32_t n, u_int32_t m, int i) {
    struct route_element *element = malloc(sizeof(struct route_element));
    element->prefix = p;
    element->next_hop = n;
    element->mask = m;
    element->interface = i;
    return element;
}


#endif //ROUTER_ROUTE_TABLE_H
