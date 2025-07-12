#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum bpf_syntax_node_type {
    BPF_SYNTAX_NODE_INVALID = 0,          ///< 无效节点
    BPF_SYNTAX_NODE_OPERATOR_COMPARISON,  ///< 比较运算符节点
    BPF_SYNTAX_NODE_FIELD,                ///< 字段节点
    BPF_SYNTAX_NODE_CONSTANT,             ///< 常量节点
    BPF_SYNTAX_NODE_JUMP_IF,     ///< 条件跳转节点，左为条件，右为跳转目标
    BPF_SYNTAX_NODE_JUMP_LABEL,  ///< 跳转标签节点
    BPF_SYNTAX_NODE_RIGHT_SUB_EXPRESSION,  ///< 右子表达式节点
};

enum {
    BPF_REGISTER_CR,  ///< 比较结寄器
    BPF_REGISTER_R0,
    BPF_REGISTER_R1,
    BPF_REGISTER_R2,
    BPF_REGISTER_R3,
    BPF_REGISTER_R4,
    BPF_REGISTER_R5,
    BPF_REGISTER_R6,
    BPF_REGISTER_R7,
    BPF_REGISTER_R8,
    BPF_REGISTER_R9,
    BPF_REGISTER_R10,
    BPF_REGISTER_R11,
    BPF_REGISTER_R12,
    BPF_REGISTER_R13,
    BPF_REGISTER_R14,
    BPF_REGISTER_R15,
    BPF_REGISTER_INVALID = -1,  ///< 无效寄存器
};

struct bpf_syntax_node {
    enum bpf_syntax_node_type type;    ///< 节点类型
    uint8_t                   reg;     ///< 寄存器，-1 表示未分配寄存器
    char                     *str;     ///< 节点字符串表示
    struct bpf_syntax_node   *parent;  ///< 父节点
    struct bpf_syntax_node   *left;    ///< 左子节点
    struct bpf_syntax_node   *right;   ///< 右子节点
};

struct bpf_syntax_tree {
    struct bpf_syntax_node *root;
    size_t                  node_count;
};

/**
 * @brief 注册字段
 *
 * @param name 字段名称
 * @param argn 字段从第几个参数传入
 * @param size 字段大小
 * @param offset 字段在参数中的偏移量
 * @return int 0 成功，-1 失败
 */
int bpf_syntax_register_field(const char *name, uint8_t argn, uint8_t size, uint32_t offset);

/**
 * @brief 创建一个新的 BPF 语法节点
 *
 * @param type 结点类型
 * @param str 结点字符串表示
 * @return struct bpf_syntax_node* 结点指针
 */
struct bpf_syntax_node *bpf_syntax_node_new(enum bpf_syntax_node_type type, char *str);

/**
 * @brief 后序遍历语法树
 *
 * @param node 语法树根节点
 * @param callback 回调函数，处理每个节点，当返回值为 0 时继续遍历，为 -1 时停止遍历
 * @param arg 回调函数的参数
 * @return int 0 成功遍历；-1 遍历被中断
 */
int bpf_syntax_tree_post_order(struct bpf_syntax_node *node,
                               int (*callback)(struct bpf_syntax_node *, void *),
                               void *arg);

/**
 * @brief 生成 BPF 汇编
 */
void bpf_syntax_asm(struct bpf_syntax_node *node);

#ifdef __cplusplus
}
#endif