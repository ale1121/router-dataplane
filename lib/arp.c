#include "utils.h"


void send_arp_reply(struct arp_header *request_header, int interface) {
	char *reply = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
	struct ether_header *eth_hdr = (struct ether_header *)reply;
	struct arp_header *arp_hdr = (struct arp_header *)(reply + sizeof(struct ether_header));

	uint8_t src_mac[MAC_SIZE];
	get_interface_mac(interface, src_mac);

	memcpy(eth_hdr->ether_dhost, request_header->sha, MAC_SIZE);
	memcpy(eth_hdr->ether_shost, src_mac, MAC_SIZE);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	arp_hdr->htype = htons(HTYPE_ETH);
	arp_hdr->ptype = htons(PTYPE_IP);
	arp_hdr->hlen = MAC_SIZE;
	arp_hdr->plen = PLEN_IPV4;
	arp_hdr->op = htons(OP_ARP_REPLY);
	memcpy(arp_hdr->sha, src_mac, MAC_SIZE);
	arp_hdr->spa = htonl(get_interface_ip_int(interface));
	memcpy(arp_hdr->tha, request_header->sha, MAC_SIZE);
	arp_hdr->tpa = request_header->spa;

	send_to_link(interface, reply, sizeof(struct ether_header) + sizeof(struct arp_header));
	free(reply);
}

void send_arp_request(struct route_table_entry *route) {
	char *request = malloc(sizeof(struct ether_header) + sizeof(struct arp_header));
	struct ether_header *eth_hdr = (struct ether_header *)request;
	struct arp_header *arp_hdr = (struct arp_header *)(request + sizeof(struct ether_header));

	uint8_t src_mac[MAC_SIZE];
	get_interface_mac(route->interface, src_mac);

	uint8_t broadcast_mac[MAC_SIZE] = BROADCAST_MAC;
	uint8_t zero_mac[MAC_SIZE] = ZERO_MAC;

	memcpy(eth_hdr->ether_dhost, broadcast_mac, MAC_SIZE);
	memcpy(eth_hdr->ether_shost, src_mac, MAC_SIZE);
	eth_hdr->ether_type = htons(ETHERTYPE_ARP);

	arp_hdr->htype = htons(HTYPE_ETH);
	arp_hdr->ptype = htons(PTYPE_IP);
	arp_hdr->hlen = MAC_SIZE;
	arp_hdr->plen = PLEN_IPV4;
	arp_hdr->op = htons(OP_ARP_REQUEST);
	memcpy(arp_hdr->sha, src_mac, MAC_SIZE);
	arp_hdr->spa = htonl(get_interface_ip_int(route->interface));
	memcpy(arp_hdr->tha, zero_mac, MAC_SIZE);
	arp_hdr->tpa = route->next_hop;

	send_to_link(route->interface, request, sizeof(struct ether_header) + sizeof(struct arp_header));
	free(request);
}

void resend_queued_packets() {
	int unchecked = queue_len;

	while(unchecked != 0) {
		struct queue_elem *elem = queue_deq(packet_queue);
		unchecked--;

		struct arp_table_entry *arp_entry = get_arp_entry(elem->route->next_hop);

		if (arp_entry == NULL) {
			// if address is still unknown, add packet back to queue
			queue_enq(packet_queue, elem);
			elem = queue_deq(packet_queue);
			continue;
		}

		struct ether_header *eth_header = (struct ether_header *)elem->packet;

		uint8_t src_mac[MAC_SIZE];
		get_interface_mac(elem->route->interface, src_mac);

		memcpy(eth_header->ether_dhost, arp_entry->mac, MAC_SIZE);
		memcpy(eth_header->ether_shost, src_mac, MAC_SIZE);

		send_to_link(elem->route->interface, elem->packet, elem->len);

		queue_len--;
		free(elem);
	}
}

void process_arp_reply(struct arp_header *reply_header) {
	// ensure the address isn't already in the arp table
	struct arp_table_entry *arp_entry = get_arp_entry(reply_header->spa);
	if (arp_entry != NULL) {
		return;
	}

	// add new address to arp table
	arp_table[arp_table_len].ip = reply_header->spa;
	memcpy(arp_table[arp_table_len].mac, reply_header->sha, MAC_SIZE);
	arp_table_len++;

	if (queue_empty(packet_queue)) {
		return;
	}

	resend_queued_packets();
}
