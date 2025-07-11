#include "syntax.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct register_usage {
    uint64_t bitmap;  // 每一位代表一个寄存器的使用情况
};

static int register_usage_get_free(struct register_usage *reg_usage) {
    // 查找第一个未使用的寄存器
    for (int i = 0; i < 64; i++) {
        uint64_t mask = 1ULL << i;
        if (!(reg_usage->bitmap & mask)) {
            reg_usage->bitmap |= mask;   // 标记为已使用
            return BPF_REGISTER_R0 + i;  // 返回寄存器编号
        }
    }

    return BPF_REGISTER_INVALID;  // 没有可用寄存器
}

/**
 * @brief 生成比较操作的 BPF 汇编代码
 *
 * @param reg_usage 寄存器使用情况
 * @param op 比较操作符，例如 "==", "!=", "<", ">", "<=", ">="
 * @param left_reg 左侧寄存器编号
 * @param right_reg 右侧寄存器编号
 */
static int bpf_node_asm_operator_comparison(struct register_usage *reg_usage,
                                            const char            *op,
                                            int                    left_reg,
                                            int                    right_reg) {
    printf("%16s: r%d %s r%d\n", "compare", left_reg, op, right_reg);
    return BPF_REGISTER_CR;  // 返回比较寄存器编号
}

/**
 * @brief 生成加载 field 的 BPF 汇编代码
 *
 * @param reg_usage 寄存器使用情况
 * @param field 字段名称
 * @return 返回寄存器编号，-1 表示没有可用寄存器
 */
static int bpf_node_asm_field(struct register_usage *reg_usage, const char *field) {
    // 从 reg_usage 找出可用的寄存器
    int reg = register_usage_get_free(reg_usage);
    if (reg < 0) {
        fprintf(stderr, "No available registers for field: %s\n", field);
        return BPF_REGISTER_INVALID;
    }

    printf("%16s: %s -> r%d\n", "load", field, reg);
    return reg;  // 返回寄存器编号
}

/**
 * @brief 生成加载常量的 BPF 汇编代码
 *
 * @param reg_usage 寄存器使用情况
 * @param constant 常量值
 * @return 返回寄存器编号，-1 表示没有可用寄存器
 */
static int bpf_node_asm_constant(struct register_usage *reg_usage, const char *constant) {
    // 从 reg_usage 找出可用的寄存器
    int reg = register_usage_get_free(reg_usage);
    if (reg < 0) {
        fprintf(stderr, "No available registers for constant: %s\n", constant);
        return BPF_REGISTER_INVALID;
    }

    printf("%16s: %s -> r%d\n", "set", constant, reg);
    return reg;  // 返回寄存器编号
}

/**
 * @brief 生成条件跳转的 BPF 汇编代码
 *
 * @param reg_usage 寄存器使用情况
 * @param node 结点
 */
static void bpf_node_asm_jump_if(struct register_usage        *reg_usage,
                                 const struct bpf_syntax_node *node) {
    assert(BPF_SYNTAX_NODE_JUMP_IF == node->type);
    assert(node->right && node->right->type == BPF_SYNTAX_NODE_JUMP_LABEL);
    assert(node->left && node->left->reg == BPF_REGISTER_CR);
    if (strcmp(node->str, "&&") == 0) {
        printf("%16s: %s\n", "jump_if_true", "+3");  // 向前跳转 3 个指令
        printf("%16s: 0 -> r0\n", "set");            // 设置 r0 为 0，用于返回结果
    } else if (strcmp(node->str, "||") == 0) {
        printf("%16s: %s\n", "jump_if_false", "+3");  // 向前跳转 3 个指令
        printf("%16s: 1 -> r0\n", "set");             // 设置 r0 为 0，用于返回结果
    } else {
        fprintf(stderr, "Unknown jump condition: %s\n", node->str);
        return;
    }

    printf("%16s\n", "ret");  // 返回指令
}

/**
 * @brief 生成右子表达式的 BPF 汇编代码
 *
 * @param reg_usage 寄存器使用情况
 * @param node 结点
 */
static void bpf_node_asm_right_sub_expression(struct register_usage        *reg_usage,
                                              const struct bpf_syntax_node *node) {
    assert(node->type == BPF_SYNTAX_NODE_RIGHT_SUB_EXPRESSION);
    printf("%16s: cs -> r0\n", "mov");
}

static void bpf_node_asm(struct bpf_syntax_node *node, void *arg) {
    struct register_usage *reg_usage = (struct register_usage *)arg;

    switch (node->type) {
    case BPF_SYNTAX_NODE_INVALID:
        fprintf(stderr, "Invalid node\n");
        break;
    case BPF_SYNTAX_NODE_OPERATOR_COMPARISON:
        node->reg = bpf_node_asm_operator_comparison(
            reg_usage, node->str, node->left->reg, node->right->reg);
        break;
    case BPF_SYNTAX_NODE_FIELD:
        node->reg = bpf_node_asm_field(reg_usage, node->str);
        break;
    case BPF_SYNTAX_NODE_CONSTANT:
        node->reg = bpf_node_asm_constant(reg_usage, node->str);
        break;
    case BPF_SYNTAX_NODE_JUMP_IF:
        bpf_node_asm_jump_if(reg_usage, node);
        break;
    case BPF_SYNTAX_NODE_JUMP_LABEL:
        break;
    case BPF_SYNTAX_NODE_RIGHT_SUB_EXPRESSION:
        bpf_node_asm_right_sub_expression(reg_usage, node);
        break;
    default:
        fprintf(stderr, "Unknown node type\n");
        break;
    }
}

struct bpf_syntax_node *bpf_syntax_node_new(enum bpf_syntax_node_type type, char *str) {
    struct bpf_syntax_node *node = (struct bpf_syntax_node *)malloc(sizeof(struct bpf_syntax_node));
    node->type                   = type;
    node->reg                    = -1;
    node->str                    = str;
    node->parent                 = NULL;
    node->left                   = NULL;
    node->right                  = NULL;
    return node;
}

void bpf_syntax_tree_post_order(struct bpf_syntax_node *node,
                                void (*callback)(struct bpf_syntax_node *node, void *arg),
                                void *arg) {
    if (!node) {
        return;
    }

    bpf_syntax_tree_post_order(node->left, callback, arg);
    bpf_syntax_tree_post_order(node->right, callback, arg);
    callback(node, arg);
}

void bpf_syntax_asm(struct bpf_syntax_node *node) {
    struct register_usage reg_usage = {0};  // 每一位代表一个寄存器的使用情况
    bpf_syntax_tree_post_order(node, bpf_node_asm, &reg_usage);
    printf("%16s\n", "ret");  // 最终返回 r0 的值
}