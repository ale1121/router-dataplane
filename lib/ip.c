#include "utils.h"


// returns 0 if checksum fails
int verify_checksum(struct iphdr *ip_hdr, size_t len) {
	uint16_t packet_checksum = ntohs(ip_hdr->check);
	ip_hdr->check = 0;
	if (packet_checksum != checksum((uint16_t *)ip_hdr, sizeof(struct iphdr))) {
		return 0;
	}
	ip_hdr->check = htons(packet_checksum);
	return 1;
}

// returns 0 if ttl is up
int decrement_ttl(struct iphdr *ip_hdr) {
	if (ip_hdr->ttl <= 1) {
		return 0;
	}
	ip_hdr->ttl--;
	ip_hdr->check = ~(~ip_hdr->check + ~((uint16_t)ip_hdr->ttl + 1) + (uint16_t)ip_hdr->ttl) - 1;
	return 1;
}

void set_ether_header(char *packet, uint8_t dest[MAC_SIZE], int interface) {
	struct ether_header *eth_hdr = (struct ether_header *)packet;

	uint8_t src_mac[MAC_SIZE];
	get_interface_mac(interface, src_mac);

	memcpy(eth_hdr->ether_dhost, dest, MAC_SIZE);
	memcpy(eth_hdr->ether_shost, src_mac, MAC_SIZE);
}

void send_ip_packet(char *packet, size_t len, int interface) {
	struct iphdr *ip_hdr = (struct iphdr *)(packet + sizeof(struct ether_header));

	if (!verify_checksum(ip_hdr, len)) {
		return;
	}

	// check if the packet is an IMCP for the router
	uint32_t interface_ip = get_interface_ip_int(interface);
	if (ntohl(ip_hdr->daddr) == interface_ip) {
		if (ip_hdr->protocol == PROTOCOL_ICMP) {
			process_icmp_packet(packet, len, interface);
		}
		return;
	}

	if (!decrement_ttl(ip_hdr)) {
		send_icmp_message(packet, interface, ICMP_TIME_EXCEEDED);
		return;
	}

	struct route_table_entry *best_route = get_entry(routing_trie, ip_hdr->daddr);
	if (best_route == NULL) {
		send_icmp_message(packet, interface, ICMP_DEST_UNREACHABLE);
		return;
	}

	struct arp_table_entry *arp_entry = get_arp_entry(best_route->next_hop);
	if (arp_entry == NULL) {
		// save packet and send an ARP request
		struct queue_elem *elem = malloc(sizeof(struct queue_elem));
	
		memcpy(elem->packet, packet, len);
		elem->len = len;
		elem->route = best_route;
		queue_enq(packet_queue, elem);
		queue_len++;

		send_arp_request(best_route);
		return;
	}

	set_ether_header(packet, arp_entry->mac, best_route->interface);

	send_to_link(best_route->interface, packet, len);
}