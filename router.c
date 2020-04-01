#include "skel.h"
#include "arp.h"
#include "queue.h"
#include "arp_table.h"
#include "route_table.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

void printIp(uint32_t ip) {
    unsigned char bytes[4];
    bytes[3] = ip & 0xFF;
    bytes[2] = (ip >> 8) & 0xFF;
    bytes[1] = (ip >> 16) & 0xFF;
    bytes[0] = (ip >> 24) & 0xFF;
    printf("%d.%d.%d.%d\n", bytes[3], bytes[2], bytes[1], bytes[0]);
}


struct route_element* parse_table() {
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
}

uint8_t * get_mac_from_index(struct arp_vector *arp_table, int index) {
    return arp_table->table[index].mac;
}

struct arp_vector * init_arp_table() {
    struct arp_vector * arp_table  = malloc(sizeof(struct arp_vector));
    arp_table->table = malloc(sizeof(struct arp_element) * 50000);
    arp_table->size = 0;
    return arp_table;
}

void add_arp_entry(struct arp_vector *arp_table, uint8_t * ip, uint8_t * mac) {
    struct arp_element *new_entry = create_arp_element(ip, mac);
    arp_table->table[arp_table->size] = *new_entry;
    arp_table->size = arp_table->size + 1;
}     // TODO + param IP and MAC

void process_arp_request(packet m) {
    printf("got request ===> make reply \n");

    struct ether_header *ethernet = (struct ether_header *)m.payload;
    struct _arp_hdr *arp = (struct _arp_hdr *) (m.payload + ETH_OFF);
    char * router_ip = get_interface_ip(m.interface);


    struct in_addr requested_ip;
    inet_aton(router_ip, &requested_ip);
    if (memcmp(&requested_ip, arp->target_ip, 4) == 0) {   // verific daca requestul venit prin broadcast este destinat router
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
        for (int i = 0; i < 4; ++i) {
            arp->target_ip[i] = arp->sender_ip[i];
            arp->sender_ip[i] = router_ip[i];
        }
        send_packet(m.interface, &m);
    }
}

void process_arp_reply(packet m, struct arp_vector *arp_table, queue q) {
    printf("reply ===> send reply back ! \n");
    struct ether_header *ethernet = (struct ether_header *)m.payload;
    struct _arp_hdr *arp = (struct _arp_hdr *) (m.payload + ETH_OFF);

    add_arp_entry(arp_table, arp->sender_ip, arp->sender_mac);

    while (!queue_empty(q) && search_arp(arp_table, ((struct _arp_hdr *)(((packet *)queue_top(q))->payload + ETH_OFF))->target_ip) != -1) {
        packet * temp = (packet *)queue_top(q);
        uint8_t * mac = get_mac_from_index(arp_table, search_arp(arp_table, ((struct _arp_hdr *)(((packet *)queue_top(q))->payload + ETH_OFF))->target_ip));

        struct ether_header *e = (struct ether_header *)(*temp).payload;
        struct _arp_hdr *a = (struct _arp_hdr *) ((*temp).payload + ETH_OFF);
        for (int i = 0; i < 6; ++i) {
            e->ether_dhost[i] = mac[i];
            a->target_mac[i] = mac[i];
        }
        queue_deq(q);
        send_packet(m.interface, temp);
    }
}

void process_ip(packet m, struct arp_vector *arp_table, queue q){
    struct ether_header *ethernet = (struct ether_header *)m.payload;
    struct iphdr *ip = (struct iphdr *)(m.payload + IP_OFF);
    struct icmphdr *icmp = (struct icmphdr *)(m.payload + ICMP_OFF);
    // iau din ip destinatar ip
    // daca nu  e in arp table dau drop
    // daca este iau interfata
    // ma uit sa vad daca am mac, daca da trimit pe interfata
    // daca nu, fac arp request si bag mesaj in coada



}

int main(int argc, char *argv[])
{
    packet m;
	int rc;

	init();
    struct route_element *routing_table = parse_table();  // routing_table[0].prefix
    struct arp_vector *arp_table = init_arp_table();


    queue q = queue_create();
//    int x = 100;
//    int *  ceva2 = &x;
//    queue_enq(q,  ceva2);
//    printf("%d \n",  *(int *)  queue_top(q));
//    queue_deq(q);


//     uint8_t *prefix = malloc(sizeof(uint8_t) * 4);
//     inet_aton("192.1.15.0", prefix);
//     struct route_element *entry = get_best_route(routing_table,  *((uint32_t*)prefix));
//
//     if(entry == NULL) {
//     	printf("haos\n");
//     } else {
//     	printf("Interface is %d \n", entry->interface);
//     }

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
                process_ip(m, arp_table, q);
                break;
        }

	}
}
