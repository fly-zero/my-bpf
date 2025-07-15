#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

enum bpf_ast_node_type {
    BPF_AST_NODE_INVALID = 0,  ///< 无效节点
    BPF_AST_NODE_COMPARISON,   ///< 比较运算符节点
    BPF_AST_NODE_FIELD,        ///< 字段节点
    BPF_AST_NODE_CONSTANT,     ///< 常量节点
    BPF_AST_NODE_IF,           ///< 条件语句节点
    BPF_AST_NODE_IF_FALSE,     ///< 条件语句的否定节点
};

struct bpf_ast_node {
    enum bpf_ast_node_type type;       ///< 节点类型
    uint8_t                reg;        ///< 寄存器，-1 表示未分配寄存器
    uint8_t                instr_len;  ///< 占用的指令长度
    uint16_t               pc;         ///< 当前结生成汇编的程序计数器
    char                  *str;        ///< 节点字符串表示
    struct bpf_ast_node   *parent;     ///< 父节点
    struct bpf_ast_node   *left;       ///< 左子节点
    struct bpf_ast_node   *right;      ///< 右子节点
};

struct bpf_compilation_context;

/**
 * @brief 分配编译上下文
 */
struct bpf_compilation_context *bpf_compilation_context_new();

/**
 * @brief 释放编译上下文
 *
 * @param context 编译上下文
 */
void bpf_compilation_context_free(struct bpf_compilation_context *context);

/**
 * @brief 注册字段
 *
 * @param name 字段名称
 * @param argn 字段从第几个参数传入
 * @param size 字段大小，单位为字节，1、2、4 或 8
 * @param offset 字段在参数中的偏移量
 * @return int 0 成功，-1 失败
 */
int bpf_ast_register_field(const char *name, uint8_t argn, uint8_t size, uint16_t offset);

/**
 * @brief 创建一个新的 BPF 语法节点
 *
 * @param context 编译上下文
 * @param type 结点类型
 * @param str 结点字符串表示
 * @return struct bpf_ast_node* 结点指针
 */
struct bpf_ast_node *bpf_ast_node_new(struct bpf_compilation_context *context,
                                      enum bpf_ast_node_type          type,
                                      char                           *str);

/**
 * @brief 释放 BPF 语法节点
 * @param node 结点指针
 */
void bpf_ast_node_free(struct bpf_compilation_context *context, struct bpf_ast_node *node);

/**
 * @brief 后序遍历语法树
 *
 * @param node 语法树根节点
 * @param callback 回调函数，处理每个节点，当返回值为 0 时继续遍历，为 -1 时停止遍历
 * @param arg 回调函数的参数
 * @return int 0 成功遍历；-1 遍历被中断
 */
int bpf_ast_tree_post_order(struct bpf_ast_node *node,
                            int (*callback)(struct bpf_compilation_context *,
                                            struct bpf_ast_node *),
                            struct bpf_compilation_context *ctx);

/**
 * @brief 生成 BPF 汇编
 *
 * @param context 编译上下文
 * @param node 语法树根节点
 * @return int 0 成功，-1 失败
 */
int bpf_assemble(struct bpf_compilation_context *context, struct bpf_ast_node *node);

/**
 * @brief 反汇编 BPF 程序
 *
 * @param context 编译上下文
 * @param callback 回调函数，用于处理每条指令的反汇编结果
 * @param arg 回调函数的参数
 * @return int 0 成功，-1 失败
 */
int bpf_disassemble(const struct bpf_compilation_context *context,
                    void (*callback)(const char *, size_t, uint16_t, void *),
                    void *arg);

#ifdef __cplusplus
}
#endif