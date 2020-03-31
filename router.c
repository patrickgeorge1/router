#include "skel.h"
#include "arp.h"
#include "route_table.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

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

void process_arp_request(packet m) {
    printf("got request ===> make broadcast \n");

    struct ether_header *ethernet = (struct ether_header *)m.payload;
    struct _arp_hdr *arp = (struct _arp_hdr *) (m.payload + ETH_OFF);
    char * router_ip = get_interface_ip(m.interface);

    // ether si arp a ajuns
    // acum fac reply


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

void process_arp_reply(packet m) {
    printf("reply ===> send reply back ! \n");

    packet pkt;
    memset((&pkt)->payload, 0, sizeof((&pkt)->payload));
    (&pkt)->len = 0;

    struct ether_header * ethernet = (struct ether_header *)pkt.payload;
    struct _arp_hdr * arp = (struct _arp_hdr *) (pkt.payload + ETH_OFF);
}

int main(int argc, char *argv[])
{
    packet m;
	int rc;

	init();
    struct route_element *routing_table = parse_table();  // routing_table[0].prefix


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
                    // MAC to                   ff.ff.ff.ff.ff  ethernet
                    // MAC from                 router          ethernet


                    // MAC from                 router         arp
                    // IP  from                 router         arp
                    // MAC to                   00.00.00.00    arp
                    // IP  to                   host           arp
                    process_arp_request(m);
                }
                else // daca  primeste reply ----> dau request sau forwarding
                {
                    // primesc reply de la vreun host
                    // daca am mac destinatie, completez si il fau
                    // daca nu il am, trebuie obtinut prin broadcasting

                    process_arp_reply(m);
                }
                break;

            case ETHERTYPE_IP:
                ip_hdr_response = (struct iphdr *)(m.payload + IP_OFF);
                icmp_hdr_response = (struct icmphdr *)(m.payload + ICMP_OFF);
                break;
        }

	}
}
