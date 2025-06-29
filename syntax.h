#pragma once

#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

enum bpf_syntax_node_type
{
    BPF_SYNTAX_NODE_INVALID = 0,
    BPF_SYNTAX_NODE_OPERATOR_COMPARISON,
    BPF_SYNTAX_NODE_FIELD,
    BPF_SYNTAX_NODE_CONSTANT,
    BPF_SYNTAX_NODE_OPERATOR_LOGICAL,
};

struct bpf_syntax_node
{
    enum bpf_syntax_node_type type;    ///< 节点类型
    char                     *str;     ///< 节点字符串表示
    struct bpf_syntax_node   *parent;  ///< 父节点
    struct bpf_syntax_node   *left;    ///< 左子节点
    struct bpf_syntax_node   *right;   ///< 右子节点
};

struct bpf_syntax_tree
{
    struct bpf_syntax_node *root;
    size_t node_count;
};

struct bpf_syntax_tree *bpf_syntax_tree_new(void);

struct bpf_syntax_node *bpf_syntax_node_new(enum bpf_syntax_node_type type,
                                            const char *str,
                                            size_t len);

#ifdef __cplusplus
}
#endif