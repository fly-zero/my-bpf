#include "syntax.h"

#include <stdlib.h>
#include <string.h>

struct bpf_syntax_node *bpf_syntax_node_new(enum bpf_syntax_node_type type,
                                            const char *str,
                                            size_t len) {
  struct bpf_syntax_node *node =
      (struct bpf_syntax_node *)malloc(sizeof(struct bpf_syntax_node));
  node->type = type;
  node->str = strndup(str, len);
  node->parent = NULL;
  node->left = NULL;
  node->right = NULL;
  return node;
}