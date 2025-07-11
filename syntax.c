#include "syntax.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/**
 * @brief 链表节点结构体
 */
struct bpf_list_node {
    struct bpf_list_node *prev;  ///< 上一个节点
    struct bpf_list_node *next;  ///< 下一个节点
};

/**
 * @brief 寄存器使用情况结构体
 */
struct bpf_register_usage {
    uint64_t bitmap;  // 每一位代表一个寄存器的使用情况
};

/**
 * @brief 字段属性结构体
 */
struct bpf_syntax_field_attr {
    struct bpf_list_node list_hook;  ///< 链表钩子，用于链表管理
    char                *name;       ///< 字段名称
    uint8_t              argn;       ///< 字段地址所在参数编号
    uint8_t              size;       ///< 字段大小
    uint32_t             offset;     ///< 字段相对于参数的偏移量
};

/**
 * @brief 字段节点结构体
 */
struct bpf_syntax_field_node {
    struct bpf_syntax_node              node;  ///< 基类
    const struct bpf_syntax_field_attr *attr;  ///< 字段属性
};

/**
 * @brief 寄存器编号到名称的映射
 */
static const char *s_bpf_register_names[] = {
    "CR",
    "R0",
    "R1",
    "R2",
    "R3",
    "R4",
    "R5",
    "R6",
    "R7",
};

static struct bpf_list_node s_bpf_field_attr_list = {
    .prev = &s_bpf_field_attr_list, .next = &s_bpf_field_attr_list};  ///< 全局字段链表头

static const char *bpf_register_name(int reg) {
    // 检查寄存器编号是否在有效范围内
    if (reg < BPF_REGISTER_CR || reg > BPF_REGISTER_R7) {
        return "INVALID";
    }

    return s_bpf_register_names[reg];  // 返回寄存器名称
}

static int bpf_register_usage_get_free(struct bpf_register_usage *reg_usage) {
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
static int bpf_node_asm_operator_comparison(struct bpf_register_usage *reg_usage,
                                            const char                *op,
                                            int                        left_reg,
                                            int                        right_reg) {
    printf("%16s: r%d %s r%d\n", "compare", left_reg, op, right_reg);
    return BPF_REGISTER_CR;  // 返回比较寄存器编号
}

/**
 * @brief 由参数编号转换为寄存器编号
 */
static int bpf_argn_to_reg(uint8_t argn) {
    // 将参数编号转换为寄存器编号
    // R7 ~ R6 对应参数 0 ~ 1
    if (argn == 0) {
        return BPF_REGISTER_R7;  // 第一个参数对应 R7
    } else if (argn == 1) {
        return BPF_REGISTER_R6;  // 第二个参数对应 R6
    } else {
        return BPF_REGISTER_INVALID;  // 无效参数编号
    }
}

/**
 * @brief 生成加载 field 的 BPF 汇编代码
 *
 * @param reg_usage 寄存器使用情况
 * @param field 字段名称
 * @return 成功时返回 0，失败时返回 -1
 */
static int bpf_node_asm_field(struct bpf_register_usage *reg_usage, struct bpf_syntax_node *node) {
    assert(node->type == BPF_SYNTAX_NODE_FIELD);

    struct bpf_syntax_field_node *field = (struct bpf_syntax_field_node *)node;

    // 从 reg_usage 找出可用的寄存器
    int reg = bpf_register_usage_get_free(reg_usage);
    if (reg < 0) {
        fprintf(stderr, "No available registers for field: %s\n", node->str);
        return -1;
    }

    const struct bpf_syntax_field_attr *attr = field->attr;
    assert(attr);
    printf("%16s: [%s:%u:%hhu] -> r%d\n",  // [reg:offset:size] -> reg
           "load",
           bpf_register_name(bpf_argn_to_reg(attr->argn)),
           attr->offset,
           attr->size,
           reg);      // 加载字段到寄存器
    node->reg = reg;  // 设置结点的寄存器编号
    return 0;
}

/**
 * @brief 生成加载常量的 BPF 汇编代码
 *
 * @param reg_usage 寄存器使用情况
 * @param constant 常量值
 * @return 返回寄存器编号，-1 表示没有可用寄存器
 */
static int bpf_node_asm_constant(struct bpf_register_usage *reg_usage, const char *constant) {
    // 从 reg_usage 找出可用的寄存器
    int reg = bpf_register_usage_get_free(reg_usage);
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
static void bpf_node_asm_jump_if(struct bpf_register_usage    *reg_usage,
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
static void bpf_node_asm_right_sub_expression(struct bpf_register_usage    *reg_usage,
                                              const struct bpf_syntax_node *node) {
    assert(node->type == BPF_SYNTAX_NODE_RIGHT_SUB_EXPRESSION);
    printf("%16s: cs -> r0\n", "mov");
}

static int bpf_node_asm(struct bpf_syntax_node *node, void *arg) {
    struct bpf_register_usage *reg_usage = (struct bpf_register_usage *)arg;

    switch (node->type) {
    case BPF_SYNTAX_NODE_OPERATOR_COMPARISON:
        node->reg = bpf_node_asm_operator_comparison(
            reg_usage, node->str, node->left->reg, node->right->reg);
        return 0;
    case BPF_SYNTAX_NODE_FIELD:
        return bpf_node_asm_field(reg_usage, node);
    case BPF_SYNTAX_NODE_CONSTANT:
        node->reg = bpf_node_asm_constant(reg_usage, node->str);
        return 0;
    case BPF_SYNTAX_NODE_JUMP_IF:
        bpf_node_asm_jump_if(reg_usage, node);
        return 0;
    case BPF_SYNTAX_NODE_JUMP_LABEL:
        return 0;
    case BPF_SYNTAX_NODE_RIGHT_SUB_EXPRESSION:
        bpf_node_asm_right_sub_expression(reg_usage, node);
        return 0;
    default:
        fprintf(stderr, "Invalid node\n");
        return -1;
    }
}

const struct bpf_syntax_field_attr *bpf_field_attr_find(const char *name) {
    // 在全局字段链表中查找字段属性
    for (struct bpf_list_node *node = s_bpf_field_attr_list.next; node != &s_bpf_field_attr_list;
         node                       = node->next) {
        struct bpf_syntax_field_attr *attr = (struct bpf_syntax_field_attr *)node;
        if (strcmp(attr->name, name) == 0) {
            return attr;  // 找到匹配的字段属性
        }
    }

    return NULL;  // 未找到字段属性
}

static struct bpf_syntax_node *bpf_syntax_field_node_new(char *str) {
    // 查找全局字段链表中是否已存在同名字段
    const struct bpf_syntax_field_attr *attr = bpf_field_attr_find(str);
    if (!attr) {
        fprintf(stderr, "Field %s not registered\n", str);
        return NULL;  // 字段未注册
    }

    struct bpf_syntax_field_node *field =
        (struct bpf_syntax_field_node *)malloc(sizeof(struct bpf_syntax_field_node));
    struct bpf_syntax_node *node = &field->node;  // 将基类指针指向子类
    node->type                   = BPF_SYNTAX_NODE_FIELD;
    node->reg                    = -1;
    node->str                    = str;
    node->parent                 = NULL;
    node->left                   = NULL;
    node->right                  = NULL;
    field->attr                  = attr;  // 设置字段属性
    return node;
}

static struct bpf_syntax_node *bpf_syntax_node_generic_new(enum bpf_syntax_node_type type,
                                                           char                     *str) {
    struct bpf_syntax_node *node = (struct bpf_syntax_node *)malloc(sizeof(struct bpf_syntax_node));
    node->type                   = type;
    node->reg                    = -1;
    node->str                    = str;
    node->parent                 = NULL;
    node->left                   = NULL;
    node->right                  = NULL;
    return node;
}

int bpf_syntax_register_field(const char *name, uint8_t argn, uint8_t size, uint32_t offset) {
    // 在全局字段链表中查找是否已存在同名字段
    if (bpf_field_attr_find(name)) {
        fprintf(stderr, "Field %s already registered\n", name);
        return -1;  // 字段已存在
    }

    // 创建新的字段属性
    struct bpf_syntax_field_attr *new_attr =
        (struct bpf_syntax_field_attr *)malloc(sizeof(struct bpf_syntax_field_attr));
    if (!new_attr) {
        fprintf(stderr, "Failed to allocate memory for field attribute\n");
        return -1;  // 内存分配失败
    }

    new_attr->name = strdup(name);
    if (!new_attr->name) {
        fprintf(stderr, "Failed to allocate memory for field name\n");
        free(new_attr);
        return -1;  // 内存分配失败
    }

    // 初始化字段属性
    new_attr->argn   = argn;
    new_attr->size   = size;
    new_attr->offset = offset;

    // 将新字段添加到全局字段链表中
    new_attr->list_hook.prev         = s_bpf_field_attr_list.prev;
    new_attr->list_hook.next         = &s_bpf_field_attr_list;
    s_bpf_field_attr_list.prev->next = &new_attr->list_hook;
    s_bpf_field_attr_list.prev       = &new_attr->list_hook;
    return 0;  // 成功注册字段
}

struct bpf_syntax_node *bpf_syntax_node_new(enum bpf_syntax_node_type type, char *str) {
    switch (type) {
    case BPF_SYNTAX_NODE_FIELD:
        return bpf_syntax_field_node_new(str);
    default:
        return bpf_syntax_node_generic_new(type, str);
    }
}

int bpf_syntax_tree_post_order(struct bpf_syntax_node *node,
                               int (*callback)(struct bpf_syntax_node *, void *),
                               void *arg) {
    if (!node) {
        return -1;
    }

    if (bpf_syntax_tree_post_order(node->left, callback, arg) < 0) {
        return -1;
    }

    if (bpf_syntax_tree_post_order(node->right, callback, arg) < 0) {
        return -1;
    }

    return callback(node, arg);
}

void bpf_syntax_asm(struct bpf_syntax_node *node) {
    struct bpf_register_usage reg_usage = {0};  // 每一位代表一个寄存器的使用情况

    // R7 为传的第一个参数，默认有一个参数
    reg_usage.bitmap |= (1ULL << (BPF_REGISTER_R7 - BPF_REGISTER_R0));  // 标记 R7 为已使用

    bpf_syntax_tree_post_order(node, bpf_node_asm, &reg_usage);
    printf("%16s\n", "ret");  // 最终返回 r0 的值
}

/**
 * @brief 清理函数
 */
__attribute__((destructor)) static void bpf_syntax_cleanup() {
    // 清理全局字段链表
    struct bpf_list_node *node = s_bpf_field_attr_list.next;
    while (node != &s_bpf_field_attr_list) {
        struct bpf_syntax_field_attr *attr = (struct bpf_syntax_field_attr *)node;
        node                               = node->next;
        free(attr->name);  // 释放字段名称
        free(attr);        // 释放字段属性结构体
    }
}