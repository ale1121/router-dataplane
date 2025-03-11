#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "trie.h"

#define UNREACHABLE -1


struct trie_node *create_node() {
    struct trie_node *node = malloc(sizeof(struct trie_node));
    node->children[0] = node->children[1] = NULL;
    node->route.interface = UNREACHABLE;
    return node;
}

void add_entry(struct trie_node *root, struct route_table_entry entry) {
    struct trie_node *node = root;
    uint32_t mask = entry.mask;
    uint32_t prefix = entry.prefix;
    while (mask) {
        short bit = prefix & 1;
        if (node->children[bit] == NULL) {
            node->children[bit] = create_node();
        }
        node = node->children[bit];
        mask >>= 1;
        prefix >>= 1;
    }
    if (node->route.interface == UNREACHABLE || node->route.mask < entry.mask) {
        node->route = entry;
    }
}

struct route_table_entry *get_entry(struct trie_node *root, uint32_t ip) {
    struct trie_node *node = root;
    struct trie_node *prev = NULL;
    while (node != NULL) {
        short bit = ip & 1;
        prev = node;
        node = node->children[bit];
        ip >>= 1;
    }
    if (prev->route.interface == UNREACHABLE) {
        return NULL;
    }
    return &prev->route;
}

struct trie_node *read_routing_trie(const char *path)
{
	struct trie_node *root = create_node();
	FILE *fp = fopen(path, "r");
	int i;
	char *p, line[64];

	while (fgets(line, sizeof(line), fp) != NULL) {
		p = strtok(line, " .");
		i = 0;
        struct route_table_entry entry;
		while (p != NULL) {
			if (i < 4)
				*(((unsigned char *)&entry.prefix)  + i % 4) = (unsigned char)atoi(p);

			if (i >= 4 && i < 8)
				*(((unsigned char *)&entry.next_hop)  + i % 4) = atoi(p);

			if (i >= 8 && i < 12)
				*(((unsigned char *)&entry.mask)  + i % 4) = atoi(p);

			if (i == 12)
				entry.interface = atoi(p);
			p = strtok(NULL, " .");
			i++;
		}
		add_entry(root, entry);
	}
    
    fclose(fp);
	return root;
}
