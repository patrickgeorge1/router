#include "skel.h"
#include "ip.h"
#include "arp.h"
#include "queue.h"
#include "arp_table.h"
#include "route_table.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void printIp(uint32_t ip) {   // TODO delete
    unsigned char bytes[4];
    bytes[3] = ip & 0xFF;
    bytes[2] = (ip >> 8) & 0xFF;
    bytes[1] = (ip >> 16) & 0xFF;
    bytes[0] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
}


struct route_element* parse_table() {
    // tine in memorie uint32 in host order
    struct route_element *routing_table = malloc(sizeof(struct route_element) * 65000);  //  lungime totala
    size_t bufsize = 100;
    size_t len = 0;
    ssize_t read;
    char *buffer = (char *)malloc(bufsize * sizeof(char));
    FILE *fp = fopen("rtable.txt", "r");

    int index = 0;
    while ((read = getline(&buffer, &len, fp)) != -1) {
        struct in_addr prefix;
        struct in_addr next_hop;
        struct in_addr mask;
        int interface;

        char *ptr = strtok(buffer," ");
        inet_aton(ptr, &prefix);

        ptr = strtok(NULL, " ");
        inet_aton(ptr, &next_hop);

        ptr = strtok(NULL, " ");
        inet_aton(ptr, &mask);

        ptr = strtok(NULL, " ");
        interface = atoi(ptr);

        struct route_element *element = crete_route_element(prefix.s_addr, next_hop.s_addr, mask.s_addr, interface);
        routing_table[index] = *element;
        index++;
    }
    fclose(fp);
    return routing_table;
}

int search_arp(struct arp_vector *arp_table, uint8_t * ip) {
    int found = -1;
    for (int i = 0; i < arp_table->size; ++i) {
        if (memcmp(arp_table->table[i].ip, ip, 4) == 0) {
            found = i;
            break;
        }
    }
    return found;
}

struct route_element *get_best_route(struct route_element *rtable,  uint32_t dest_ip) {
    int check_prefix;
    int position = -1;

    for(int i = 0; i < ROUTE_TABLE_SIZE; ++i) {
        check_prefix = rtable[i].mask & dest_ip;
        if(check_prefix == rtable[i].prefix) {
            if((position != -1 && rtable[position].mask <= rtable[i].mask) || position == -1) {
                position = i;
            }
        }
    }

    if(position == -1) {
        return NULL;
    }

    return &rtable[position];
}   // TODO adjutst

uint8_t * get_mac_from_index(struct arp_vector *arp_table, int index) {
    return arp_table->table[index].mac;
}

struct arp_vector * init_arp_table() {
    // le tin in network order
    struct arp_vector * arp_table  = malloc(sizeof(struct arp_vector));
    arp_table->table = malloc(sizeof(struct arp_element) * 50000);
    arp_table->size = 0;
    return arp_table;
}

void add_arp_entry(struct arp_vector *arp_table, uint8_t * ip, uint8_t * mac) {
    struct arp_element *new_entry = create_arp_element(ip, mac);
    arp_table->table[arp_table->size] = *new_entry;
    arp_table->size = arp_table->size + 1;
}

void process_arp_request(packet m) {
    printf("got request ===> make reply \n\n");


    struct ether_header *ethernet = (struct ether_header *)m.payload;
    struct _arp_hdr *arp = (struct _arp_hdr *) (m.payload + ETH_OFF);
    struct in_addr rip;
    char *router_ip = get_interface_ip(m.interface);
    inet_aton(router_ip, &rip);

//    printf("before : From   \n\n");
//    printIp(*((uint32_t*)arp->sender_ip));
//    printf("To     \n");
//    printIp(*((uint32_t*)arp->target_ip));
//    printf("AAAAAAAAAAAAAAAAA \n\n");


    if (memcmp(&rip, arp->target_ip, 4) == 0) {   // verific daca requestul venit prin broadcast este destinat router
        // eternet
        for (int i = 0; i < 6; ++i) {
            ethernet->ether_dhost[i] = ethernet->ether_shost[i];
        }
        get_interface_mac(m.interface, ethernet->ether_shost);
        ethernet->ether_type = htons(ETHERTYPE_ARP);

        // arp
        arp->htype = htons(1);
        arp->ptype = htons(ETH_P_IP);
        arp->hlen  = 6;
        arp->plen  = 4;
        arp->opcode = htons(2);  // reply
        for (int i = 0; i < 6; ++i) {
            arp->target_mac[i] = arp->sender_mac[i];
        }
        get_interface_mac(m.interface, arp->sender_mac);

        memcpy(&arp->target_ip, &arp->sender_ip, 4 * sizeof(uint8_t));
        memcpy(&arp->sender_ip, &rip, 4 * sizeof(uint8_t));  // TODO ROUTER IP

//        printf("after : From   \n\n");
//        printIp(*((uint32_t*)arp->sender_ip));
//        printf("To     \n");
//        printIp(*((uint32_t*)arp->target_ip));
//        printf("AAAAAAAAAAAAAAAAA \n\n");

        send_packet(m.interface, &m);
    }
}

void process_arp_reply(packet m, struct arp_vector *arp_table, queue q) {
    printf("reply ===> send reply back ! \n");
    struct ether_header *ethernet = (struct ether_header *)m.payload;
    struct _arp_hdr *arp = (struct _arp_hdr *) (m.payload + ETH_OFF);

    add_arp_entry(arp_table, arp->sender_ip, arp->sender_mac);
    while (!queue_empty(q)) {
        packet * firstOnQueue = (packet *) queue_top(q);
        uint8_t * mac = get_mac_from_index(arp_table, search_arp(arp_table, ((struct ip_hdr *)(firstOnQueue->payload + IP_OFF))->daddr));

        struct ether_header *e = (struct ether_header *)(*firstOnQueue).payload;

        for (int i = 0; i < 6; ++i) {
            e->ether_dhost[i] = mac[i];
        }
        queue_deq(q);
        send_packet(firstOnQueue->interface, firstOnQueue);
    }
}

uint16_t ip_checksum(void* vdata,size_t length) {
    // Cast the data pointer to one that can be indexed.
    char* data=(char*)vdata;

    // Initialise the accumulator.
    uint64_t acc=0xffff;

    // Handle any partial block at the start of the data.
    unsigned int offset=((uintptr_t)data)&3;
    if (offset) {
        size_t count=4-offset;
        if (count>length) count=length;
        uint32_t word=0;
        memcpy(offset+(char*)&word,data,count);
        acc+=ntohl(word);
        data+=count;
        length-=count;
    }

    // Handle any complete 32-bit blocks.
    char* data_end=data+(length&~3);
    while (data!=data_end) {
        uint32_t word;
        memcpy(&word,data,4);
        acc+=ntohl(word);
        data+=4;
    }
    length&=3;

    // Handle any partial block at the end of the data.
    if (length) {
        uint32_t word=0;
        memcpy(&word,data,length);
        acc+=ntohl(word);
    }

    // Handle deferred carries.
    acc=(acc&0xffffffff)+(acc>>32);
    while (acc>>16) {
        acc=(acc&0xffff)+(acc>>16);
    }

    // If the data began at an odd byte address
    // then reverse the byte order to compensate.
    if (offset&1) {
        acc=((acc&0xff00)>>8)|((acc&0x00ff)<<8);
    }

    // Return the checksum in network byte order.
    return htons(~acc);
}

void send_timeout(packet m) {
    printf(" \n   Timeout    \n");

    struct ip_hdr *ip = (struct ip_hdr *)(m.payload + IP_OFF);
    struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ICMP_OFF);

    struct in_addr rip;
    char *router_ip = get_interface_ip(m.interface);
    inet_aton(router_ip, &rip);

//
//    packet reply;
//    memset(reply.payload, 0, sizeof(reply.payload));
//    reply.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
//    reply.interface = m.interface;
//
//
//    struct ether_header *et_limit = (struct ether_header *)reply.payload;
//    struct ip_hdr *ip_limit = (struct ip_hdr *)(reply.payload + IP_OFF);
//    struct icmphdr *icmp_limit = (struct icmphdr *)(reply.payload + ICMP_OFF);
//
//
//
//    // ETHERNET
//    memcpy(&reply.payload, &m.payload, sizeof(struct ether_header) + sizeof(struct ip_hdr));
////    et_limit->ether_type = htons(ETHERTYPE_IP);
////    memcpy(&et_limit->ether_dhost, &et_limit->ether_shost, 6 * sizeof(uint8_t));
////    get_interface_mac(m.interface, et_limit->ether_shost);
//
//    // IP
//    ip_limit->version = 4; // IPv4
//    ip_limit->ihl = 5; // dimensiunea headerului in cuvinte de 32 de biti
//    ip_limit->ttl = 1;
//    ip_limit->proto = IPPROTO_ICMP;
//    ip_limit->id = htons(getpid() & 0xFFFF);
//    ip_limit->len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));
//
//    memcpy(&ip_limit->daddr, &ip->saddr, 4 * sizeof(uint8_t));
//        printf(" to  \n");
//        printIp(*((uint32_t*)ip_limit->daddr));
//
//    memcpy(&ip_limit->saddr, &rip, 4 * sizeof(uint8_t));
//        printf("  from    \n");
//        printIp(*((uint32_t*)ip_limit->saddr));
//
//    ip_limit->csum = 0;
//    ip_limit->csum = htons(ip_checksum(ip_limit, sizeof(struct iphdr)));
//
//    // ICMP
//    icmp_limit->code = 0;
//    icmp_limit->type = ICMP_TIME_EXCEEDED;
//    icmp_limit->un.echo.id = htons(getpid() & 0xFFFF);
//    icmp_limit->un.echo.sequence = htons(getpid() & 0xFFFF);
//    icmp_limit->checksum = 0;
//    icmp_limit->checksum = ip_checksum(icmp_limit, sizeof(struct icmphdr));

//    send_packet(reply.interface, &reply);


    m.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

    memcpy(&ip->daddr, &ip->saddr, 4 * sizeof(uint8_t));
    memcpy(&ip->saddr, &rip, 4 * sizeof(uint8_t));
    ip->csum = 0;
    ip->csum = htons(ip_checksum(ip, sizeof(struct iphdr)));

    icmp_hdr->type = ICMP_TIME_EXCEEDED;
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

    send_packet(m.interface, &m);
}

void sent_host_unreachable(packet m) {
    printf(" \n   No route for destination    \n");
    struct ether_header *ethernet = (struct ether_header *)m.payload;
    struct ip_hdr *ip = (struct ip_hdr *)(m.payload + IP_OFF);
    struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ICMP_OFF);


    struct in_addr rip;
    char *router_ip = get_interface_ip(m.interface);
    inet_aton(router_ip, &rip);

    m.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);


    // IP
    memcpy(&ip->daddr, &ip->saddr, 4 * sizeof(uint8_t));
    memcpy(&ip->saddr, &rip, 4 * sizeof(uint8_t));
    ip->csum = 0;
    ip->csum = htons(ip_checksum(ip, sizeof(struct iphdr)));


    // ICMP
    icmp_hdr->type = ICMP_DEST_UNREACH;
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

    send_packet(m.interface, &m);
}

void process_ip(packet m, struct arp_vector *arp_table, struct route_element* routing_table,  queue q){
    printf(" got IP  ==> forward  \n");
    struct ether_header *ethernet = (struct ether_header *)m.payload;
    struct ip_hdr *ip = (struct ip_hdr *)(m.payload + IP_OFF);

    struct icmphdr *icmp_hdr = (struct icmphdr *)(m.payload + ICMP_OFF);

    // TODO delete this if to get sent 10 packets
    if (ip->proto == IPPROTO_ICMP) {   // daca vine IP + ICMP

        struct in_addr this_router_ip;
        inet_aton(get_interface_ip(m.interface), &this_router_ip);

        // TODO bag in functie
        if (memcmp(ip->daddr, &this_router_ip.s_addr, 4) == 0 && icmp_hdr->type == ICMP_ECHO) {   // daca este adresat routerului ECHO Request
            printf(" \n   ICMP    \n");

            m.len = sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);

//            // IP
            memcpy(&ip->daddr, &ip->saddr, 4 * sizeof(uint8_t));
            memcpy(&ip->saddr, &this_router_ip, 4 * sizeof(uint8_t));
            ip->csum = 0;
            ip->csum = htons(ip_checksum(ip, sizeof(struct iphdr)));


            // ICMP
            icmp_hdr->type = ICMP_ECHOREPLY;
            icmp_hdr->checksum = 0;
            icmp_hdr->checksum = ip_checksum(icmp_hdr, sizeof(struct icmphdr));

            send_packet(m.interface, &m);
            return;
        }
    }


    __u16 control_sum =  ip->csum;   // TODO ajust
    ip->csum = 0;
    if (control_sum != ip_checksum(ip, sizeof(struct ip_hdr))) {
        return;
    }

    struct route_element * next_hop = get_best_route(routing_table, *((uint32_t*)ip->daddr));
    if (next_hop != NULL)
    {
        if (ip->ttl > 1) {
            ip->ttl--;
            ip->csum = ip_checksum(ip, sizeof(struct ip_hdr));


            if (search_arp(arp_table, ip->daddr) != -1) {   // daca am mac trimit direct

                int index = search_arp(arp_table, ip->daddr);
                uint8_t *mac = get_mac_from_index(arp_table, index);
                for (int i = 0; i < 6; ++i) {
                    ethernet->ether_dhost[i] = mac[i];  // completez mac
                }
                send_packet(next_hop->interface, &m);

            } else {   // nu am mac, fac request si adaug in coada
                packet delayedPacket;
                delayedPacket.interface = next_hop->interface;
                delayedPacket.len = m.len;
                memcpy(delayedPacket.payload, m.payload, sizeof(struct ether_header) + sizeof(struct ip_hdr));

                queue_enq(q, &delayedPacket);  // salvat in coada

                packet arpRequest;
                struct ether_header *e = (struct ether_header *) arpRequest.payload;
                struct _arp_hdr *a = (struct _arp_hdr *) (arpRequest.payload + ETH_OFF);

                // packet
                arpRequest.interface = next_hop->interface;
                arpRequest.len = sizeof(struct ether_header) + sizeof(struct _arp_hdr);

                // ethernet
                e->ether_type = htons(ETHERTYPE_ARP);
                get_interface_mac(next_hop->interface, e->ether_shost);
                for (int i = 0; i < 6; ++i) {
                    e->ether_dhost[i] = 0xff;
                }

                // arp
                a->htype = htons(1);
                a->ptype = htons(ETH_P_IP);
                a->hlen = 6;
                a->plen = 4;
                a->opcode = htons(ARPOP_REQUEST);

                char *router_ip = get_interface_ip(next_hop->interface);
                struct in_addr rip;
                inet_aton(router_ip, &rip);
                memcpy(&a->sender_ip, &rip, 4 * sizeof(uint8_t));

                for (int i = 0; i < 4; ++i) {
                    a->target_ip[i] = ip->daddr[i];
                }

                get_interface_mac(next_hop->interface, a->sender_mac);
                for (int i = 0; i < 6; ++i) {
                    a->target_mac[i] = 0x00;
                }

                send_packet(arpRequest.interface, &arpRequest);  // fac arp request
            }
        }
        else
        {
            send_timeout(m);
            return;
        }
    }
    else
    {
        sent_host_unreachable(m);
        return;
    }
}


int main(int argc, char *argv[])
{
    packet m;
    int rc;

    init();
    struct route_element *routing_table = parse_table();  // routing_table[0].prefix
    struct arp_vector *arp_table = init_arp_table();
    queue q = queue_create();

    while (1) {
        struct ether_header *eth_hdr_response;
        struct iphdr *ip_hdr_response;
        struct icmphdr *icmp_hdr_response;
        struct _arp_hdr *arp_hdr_response;

        rc = get_packet(&m);
        DIE(rc < 0, "get_message");

        eth_hdr_response = (struct ether_header *)m.payload;
        uint16_t ethType =  ntohs(eth_hdr_response->ether_type);

        switch (ethType) {
            case ETHERTYPE_ARP:
                // daca primeste request ---> fac reply
                if (ntohs(((struct _arp_hdr *) (m.payload + ETH_OFF))->opcode) == ARPOP_REQUEST)
                {
                    process_arp_request(m);
                }
                else // daca  primeste reply ----> dau request sau forwarding
                {
                    // primesc reply de la vreun host
                    // daca am mac destinatie, completez si il fau
                    // daca nu il am, trebuie obtinut prin broadcasting

                    process_arp_reply(m, arp_table, q);
                }
                break;

            case ETHERTYPE_IP:
                process_ip(m, arp_table, routing_table, q);
                break;
        }

    }
}
