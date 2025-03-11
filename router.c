#include "utils.h"


// stores route table entries
struct trie_node *routing_trie; 

struct arp_table_entry *arp_table;
int arp_table_len;

queue packet_queue;
int queue_len;


struct arp_table_entry *get_arp_entry(uint32_t ip) {
	for (int i = 0; i < arp_table_len; i++) {
		if (arp_table[i].ip == ip) {
			return &arp_table[i];
		}
	}
	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	init(argc - 2, argv + 2);

	routing_trie = read_routing_trie(argv[1]);

	arp_table = malloc(sizeof(struct arp_table_entry) * 100);
	DIE(arp_table == NULL, "malloc"); 

	packet_queue = queue_create();
	queue_len = 0;

	while (1) {
		int interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

		struct ether_header *eth_hdr = (struct ether_header *) buf;

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_IP) {
			send_ip_packet(buf, len, interface);
			continue;
		}

		if (ntohs(eth_hdr->ether_type) == ETHERTYPE_ARP) {
			struct arp_header *arp_hdr = (struct arp_header *)(buf + sizeof(struct ether_header));

			// check if the router is the destination
			if (ntohl(arp_hdr->tpa) == get_interface_ip_int(interface)) {

				if (ntohs(arp_hdr->op) == OP_ARP_REPLY) {
					process_arp_reply(arp_hdr);
				} else if (ntohs(arp_hdr->op) == OP_ARP_REQUEST) {
					send_arp_reply(arp_hdr, interface);
				}
			}
		}
	}
}

