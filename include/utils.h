#ifndef _UTILS_H_
#define _UTILS_H_

#include <arpa/inet.h>
#include <string.h>
#include "protocols.h"
#include "lib.h"
#include "queue.h"
#include "trie.h"

#define ETHERTYPE_IP	0x0800
#define ETHERTYPE_ARP	0x0806

#define ZERO_MAC		{0, 0, 0, 0, 0, 0}
#define BROADCAST_MAC	{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}

#define HTYPE_ETH		0x001
#define PTYPE_IP		0x0800

#define OP_ARP_REQUEST	0x001
#define OP_ARP_REPLY	0x002

#define PROTOCOL_ICMP	1

#define MAC_SIZE        6
#define PLEN_IPV4       4

#define ICMP_ECHO_REQUEST		8
#define ICMP_ECHO_REPLY			0
#define ICMP_DEST_UNREACHABLE	3
#define ICMP_TIME_EXCEEDED		11


extern struct trie_node *routing_trie;
extern struct arp_table_entry *arp_table;
extern int arp_table_len;
extern queue packet_queue;
extern int queue_len;

struct queue_elem {
	char packet[MAX_PACKET_LEN];
	size_t len;
	struct route_table_entry *route;
};

struct arp_table_entry *get_arp_entry(uint32_t ip);

void send_ip_packet(char *packet, size_t len, int interface);

void send_arp_reply(struct arp_header *request_header, int interface);
void send_arp_request(struct route_table_entry *route);
void process_arp_reply(struct arp_header *reply_header);

void process_icmp_packet(char *packet, size_t len, int interface);
void send_icmp_message(char *packet, int interface, uint8_t type);

#endif