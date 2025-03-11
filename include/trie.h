#ifndef _TRIE_H_
#define _TRIE_H_

#include <stdint.h>
#include "lib.h"


struct trie_node {
    struct trie_node *children[2];
    struct route_table_entry route;
};

struct route_table_entry *get_entry(struct trie_node *root, uint32_t ip);
struct trie_node *read_routing_trie(const char *path);

#endif