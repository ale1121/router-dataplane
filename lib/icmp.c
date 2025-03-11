#include "utils.h"

#define PAYLOAD_SIZE    8

#define IP_VERSION      4
#define IP_IHL          5
#define IP_TOS_DEFAULT  0
#define IP_ID           1
#define IP_FRAG_OFF     0
#define TTL             64

#define ICMP_CODE       0


void set_ether_header_(char *packet, char *reply) {
    struct ether_header *packet_eth_hdr = (struct ether_header *)packet;
    struct ether_header *reply_eth_hdr = (struct ether_header *) reply;

    memcpy(reply_eth_hdr->ether_dhost, packet_eth_hdr->ether_shost, MAC_SIZE);
    memcpy(reply_eth_hdr->ether_shost, packet_eth_hdr->ether_dhost, MAC_SIZE);
    reply_eth_hdr->ether_type = htons(ETHERTYPE_IP);
}

void set_ip_header(char *packet, char *reply, uint16_t tot_len) {
    struct iphdr *packet_ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));
    struct iphdr *reply_ip_hdr = (struct iphdr *)(reply + sizeof(struct ether_header));

    reply_ip_hdr->version = IP_VERSION;
    reply_ip_hdr->ihl = IP_IHL;
    reply_ip_hdr->tos = IP_TOS_DEFAULT;
    reply_ip_hdr->tot_len = htons(tot_len);
    reply_ip_hdr->id = htons(IP_ID);
    reply_ip_hdr->frag_off = IP_FRAG_OFF;
    reply_ip_hdr->ttl = TTL;
    reply_ip_hdr->protocol = PROTOCOL_ICMP;
    reply_ip_hdr->check = 0;
    reply_ip_hdr->saddr = packet_ip_hdr->daddr;
    reply_ip_hdr->daddr = packet_ip_hdr->saddr;

    uint16_t check = checksum((uint16_t *)reply_ip_hdr, sizeof(struct iphdr));
    reply_ip_hdr->check = htons(check);
}

void set_icmp_header(char *reply, uint8_t type) {

    struct icmphdr *reply_icmp_hdr = 
        (struct icmphdr *)(reply + sizeof(struct ether_header) + sizeof(struct iphdr));

    reply_icmp_hdr->type = type;
    reply_icmp_hdr->code = ICMP_CODE;
    reply_icmp_hdr->checksum = 0;
    reply_icmp_hdr->un.gateway = 0;
    uint16_t check = checksum((uint16_t *)reply_icmp_hdr, sizeof(struct icmphdr));
    reply_icmp_hdr->checksum = htons(check);
}

void send_echo_reply(char *request, size_t len, int interface) {
    uint8_t dest_mac[6];
    struct ether_header *eth_hdr = (struct ether_header *)request;
    memcpy(dest_mac, eth_hdr->ether_shost, MAC_SIZE);
    memcpy(eth_hdr->ether_shost, eth_hdr->ether_dhost, MAC_SIZE);
    memcpy(eth_hdr->ether_dhost, dest_mac, MAC_SIZE);

    struct iphdr *ip_hdr = (struct iphdr *)(request + sizeof(struct ether_header));
    uint32_t daddr = ip_hdr->saddr;
    ip_hdr->saddr = ip_hdr->daddr;
    ip_hdr->daddr = daddr;

    ip_hdr->check = 0;
    uint16_t ip_check = checksum((uint16_t *)ip_hdr, sizeof(struct iphdr));
    ip_hdr->check = htons(ip_check);

    struct icmphdr *icmp_hdr = (struct icmphdr *)(request + sizeof(struct ether_header) + sizeof(struct iphdr));
    icmp_hdr->type = ICMP_ECHO_REPLY;
    icmp_hdr->checksum = 0;
    uint16_t icmp_check = checksum((uint16_t *)icmp_hdr, ntohs(ip_hdr->tot_len) - sizeof(struct iphdr));
    icmp_hdr->checksum = htons(icmp_check);

    send_to_link(interface, request, len);
}

void send_icmp_message(char *packet, int interface, uint8_t type) {
    size_t len = sizeof(struct ether_header) + 2 * sizeof(struct iphdr)
                + sizeof(struct icmphdr) + PAYLOAD_SIZE;
    char *reply = malloc(len);
    set_ether_header_(packet, reply);

    uint16_t tot_len = 2 * sizeof(struct iphdr) + PAYLOAD_SIZE;
    set_ip_header(packet, reply, tot_len);

    set_icmp_header(reply, type);

    // copy ip header and 64 bits (8 bytes) from the original packet
    size_t payload_size = sizeof(struct iphdr) + PAYLOAD_SIZE;
    char *packet_payload = packet + sizeof(struct ether_header);
    char *reply_payload =
        reply + sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct icmphdr);
    memcpy(reply_payload, packet_payload, payload_size);

    send_to_link(interface, reply, len);
    free(reply);
}

void process_icmp_packet(char *packet, size_t len, int interface) {
    struct icmphdr *icmp_header =
        (struct icmphdr *)(packet + sizeof(struct ether_header) + sizeof(struct iphdr));
    
    if (icmp_header->code == ICMP_CODE && icmp_header->type == ICMP_ECHO_REQUEST) {
        send_echo_reply(packet, len, interface);
    }
}