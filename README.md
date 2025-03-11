# Router DataPlane

This project implements the data plane functionality of an IPv4 router, enabling it to forward packets, resolve MAC addresses, and handle ICMP messages.

## 1. IPv4


The ```send_ip_packet``` function handles the analysing and forwarding of packets:
- verifies checksum, drops the packet if verification fails
- processes ICMP packets destined for the router
- drops packets with TTL <= 1 and sends a_time exceeded_ message
- searches for the best route to forward the packet; if none is found, drops the packet and sends a _destination unreachable_ message
- searches for the MAC address of the next hop in the arp table; if the address is unknown, saves the packet to a queue and sends an ARP request
- modifies the ethernet header and forwardsthe packet


## 2. Longest Prefix Match

The routing table is stored in a trie for efficient lookup.
- node represent bits in the prefix mask
- an array of size 2 is used for child pointers
- addresses are stored in network order


## 3. ARP

```send_arp_reply``` - creates and sends an ARP repliy for a received request

```send_arp_request``` - broadcasts an ARP request for an unknown MAC address

```process_arp_reply``` - adds resolved MAC addresses to the ARP table and retries queued packets



## 4. ICMP

```process_icmp_packet``` - handles ICMP packets destined for the router

```send_echo_reply``` - sends ICMP echo replies for received requests

```send_icmp_message``` - sends error messages like _time exceeded_ or _destination unreachable_ 

<br>



