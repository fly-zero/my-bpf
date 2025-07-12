#include "syntax.h"

#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define bpf_container_of(ptr, type, member) ((type *)((char *)(ptr)-offsetof(type, member)))

enum {
    BPF_REGISTER_CR,  ///< 比较结果寄器
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

/**
 * @brief 链表节点结构体
 */
struct bpf_list_node {
    struct bpf_list_node *prev;  ///< 上一个节点
    struct bpf_list_node *next;  ///< 下一个节点
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
 * @brief 标签节点结构体
 */
struct bpf_syntax_label_node {
    struct bpf_syntax_node  node;       ///< 基类
    struct bpf_list_node    list_hook;  ///< 链表钩子，用于链表管理
    struct bpf_syntax_node *target;     ///< 目标节点
};

/**
 * @brief 编译上下文结构体
 */
struct bpf_compilation_context {
    uint64_t             reg_bitmap;      ///< 寄存器分配位图
    struct bpf_list_node pending_labels;  ///< 待处理的标签列表
    uint32_t             next_label_id;   ///< 下一个标签 ID，用于生成唯一标签名
    uint16_t             next_pc;         ///< 下一个程序计数器
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

static void bpf_list_append(struct bpf_list_node *list, struct bpf_list_node *node) {
    // 将节点添加到链表末尾
    node->prev       = list->prev;
    node->next       = list;
    list->prev->next = node;
    list->prev       = node;
}

static void bpf_list_unlink(struct bpf_list_node *node) {
    // 从链表中移除节点
    node->prev->next = node->next;
    node->next->prev = node->prev;
}

static const char *bpf_register_name(int reg) {
    // 检查寄存器编号是否在有效范围内
    if (reg < BPF_REGISTER_CR || reg > BPF_REGISTER_R7) {
        return "INVALID";
    }

    return s_bpf_register_names[reg];  // 返回寄存器名称
}

/**
 * @brief 分配一个未使用的寄存器
 *
 * @param reg_usage 寄存器使用情况
 * @return int 返回分配的寄存器编号，-1 表示没有可用寄存器
 */
static int bpf_asm_register_alloc(struct bpf_compilation_context *context) {
    // 查找第一个未使用的寄存器
    for (int i = 0; i < 64; i++) {
        uint64_t mask = 1ULL << i;
        if (!(context->reg_bitmap & mask)) {
            context->reg_bitmap |= mask;  // 标记为已使用
            return BPF_REGISTER_R0 + i;   // 返回寄存器编号
        }
    }

    return BPF_REGISTER_INVALID;  // 没有可用寄存器
}

/**
 * @brief 释放一个寄存器的使用标记
 *
 * @param reg_usage 寄存器使用情况
 * @param reg 寄存器编号
 */
static void bpf_asm_register_free(struct bpf_compilation_context *context, int reg) {
    assert(reg >= BPF_REGISTER_R0 && reg <= BPF_REGISTER_R7);
    uint64_t mask = 1ULL << (reg - BPF_REGISTER_R0);
    context->reg_bitmap &= ~mask;  // 清除寄存器使用标记
}

/**
 * @brief 获取下一个标签 ID
 *
 * @param context 编译上下文
 * @return uint32_t 下一个标签 ID
 */
static uint32_t bpf_asm_next_label_id(struct bpf_compilation_context *context) {
    uint32_t id = context->next_label_id++;
    return id;  // 返回下一个标签 ID
}

/**
 * @brief 获取下一个程序计数器
 *
 * @param context 编译上下文
 * @return uint32_t 下一个程序计数器
 */
static uint16_t bpf_asm_next_pc(struct bpf_compilation_context *context) {
    uint16_t pc = context->next_pc++;
    assert(pc < context->next_pc);  // 断言程序计数器不会溢出
    return pc;                      // 返回下一个程序计数器
}

/**
 * @brief 由参数编号转换为寄存器编号
 */
static int bpf_asm_argn2reg(uint8_t argn) {
    if (argn > 4) {                   // 最多支持 4 个参数
        return BPF_REGISTER_INVALID;  // 无效参数编号
    }

    return BPF_REGISTER_R0 + argn;  // 返回对应的寄存器编号
}

/**
 * @brief 生成比较操作的 BPF 汇编代码
 *
 * @param reg_usage 寄存器使用情况
 * @param node 结点
 * @return 成功时返回 0，失败时返回 -1
 */
static int bpf_node_asm_comparison(struct bpf_compilation_context *context,
                                   struct bpf_syntax_node         *node) {
    assert(node->type == BPF_SYNTAX_NODE_COMPARISON);

    // 分配 pc
    node->pc = bpf_asm_next_pc(context);

    // 输出比较操作的 BPF 汇编代码
    printf("%04hx: %-8s %s %s %s\n",
           node->pc,
           "cmp",
           bpf_register_name(node->left->reg),
           node->str,
           bpf_register_name(node->right->reg));
    node->reg = BPF_REGISTER_CR;

    // 释放左右子结点的寄存器
    bpf_asm_register_free(context, node->left->reg);
    bpf_asm_register_free(context, node->right->reg);
    return 0;
}

/**
 * @brief 生成加载 field 的 BPF 汇编代码
 *
 * @param reg_usage 寄存器使用情况
 * @param node 结点
 * @return 成功时返回 0，失败时返回 -1
 */
static int bpf_node_asm_field(struct bpf_compilation_context *context,
                              struct bpf_syntax_node         *node) {
    assert(node->type == BPF_SYNTAX_NODE_FIELD);

    struct bpf_syntax_field_node *field = (struct bpf_syntax_field_node *)node;

    // 从 reg_usage 找出可用的寄存器
    int reg = bpf_asm_register_alloc(context);
    if (reg < 0) {
        fprintf(stderr, "No available registers for field: %s\n", node->str);
        return -1;
    }

    // 分配 pc
    node->pc = bpf_asm_next_pc(context);

    const struct bpf_syntax_field_attr *attr = field->attr;
    assert(attr);
    printf("%04hx: %-8s [%s:%u:%hhu] -> %s\n",  // [reg:offset:size] -> reg
           node->pc,
           "load",
           bpf_register_name(bpf_asm_argn2reg(attr->argn)),
           attr->offset,
           attr->size,
           bpf_register_name(reg));  // 加载字段到寄存器
    node->reg = reg;                 // 设置结点的寄存器编号
    return 0;
}

/**
 * @brief 生成加载常量的 BPF 汇编代码
 *
 * @param reg_usage 寄存器使用情况
 * @param constant 常量值
 * @return 成功时返回 0，失败时返回 -1
 */
static int bpf_node_asm_constant(struct bpf_compilation_context *context,
                                 struct bpf_syntax_node         *node) {
    // 从 reg_usage 找出可用的寄存器
    int reg = bpf_asm_register_alloc(context);
    if (reg < 0) {
        fprintf(stderr, "No available registers for constant: %s\n", node->str);
        return -1;
    }

    // 分配 pc
    node->pc = bpf_asm_next_pc(context);

    printf("%04hx: %-8s %s -> %s\n", node->pc, "set", node->str, bpf_register_name(reg));
    node->reg = reg;
    return 0;
}

/**
 * @brief 生成条件跳转的 BPF 汇编代码
 *
 * @param reg_usage 寄存器使用情况
 * @return 成功时返回 0，失败时返回 -1
 */
static int bpf_node_asm_jump_if(struct bpf_compilation_context *context,
                                struct bpf_syntax_node         *node) {
    (void)context;
    // 分配 pc
    node->pc = bpf_asm_next_pc(context);

    assert(BPF_SYNTAX_NODE_JUMP_IF == node->type);
    assert(node->right && node->right->type == BPF_SYNTAX_NODE_LABEL);
    assert(node->left && node->left->reg == BPF_REGISTER_CR);
    if (strcmp(node->str, "&&") == 0) {
        printf("%04hx: %-8s %s\n", node->pc, "jmpt", node->right->str);
        printf("%04hx: %-8s 0 -> R0\n", bpf_asm_next_pc(context), "set");
    } else if (strcmp(node->str, "||") == 0) {
        printf("%04hx: %-8s %s\n", node->pc, "jmpf", node->right->str);
        printf("%04hx: %-8s 1 -> R0\n", bpf_asm_next_pc(context), "set");
    } else {
        fprintf(stderr, "Unknown jump condition: %s\n", node->str);
        return -1;
    }

    struct bpf_syntax_node *parent = node->parent;
    assert(parent && parent->type == BPF_SYNTAX_NODE_RIGHT_SUB_EXPR);
    struct bpf_syntax_node *grandparent = parent->parent;
    if (!grandparent) {
        printf("%04hx: %-8s\n", bpf_asm_next_pc(context), "ret");
    } else {
        assert(grandparent->type == BPF_SYNTAX_NODE_JUMP_IF);
        printf("%04hx: %-8s %s\n", bpf_asm_next_pc(context), "jump", grandparent->right->str);
    }

    return 0;
}

/**
 * @brief 生成标签的 BPF 汇编代码
 *
 * @param reg_usage 寄存器使用情况
 * @param node 结点
 * @return 成功时返回 0，失败时返回 -1
 */
static int bpf_node_asm_label(struct bpf_compilation_context *context,
                              struct bpf_syntax_node         *node) {
    assert(node->type == BPF_SYNTAX_NODE_LABEL);
    assert(node->parent && node->parent->type == BPF_SYNTAX_NODE_JUMP_IF);
    assert(node->parent->right == node);
    struct bpf_syntax_label_node *label = (struct bpf_syntax_label_node *)node;

    // 设置跳转目标
    struct bpf_syntax_node *grandparent = node->parent->parent;
    assert(grandparent && grandparent->type == BPF_SYNTAX_NODE_RIGHT_SUB_EXPR);
    label->target = grandparent->right;  // 设置跳转目标

    // 将标签节点添加到待处理标签列表
    bpf_list_append(&context->pending_labels, &label->list_hook);
    return 0;
}

/**
 * @brief 生成右子表达式的 BPF 汇编代码
 *
 * @param reg_usage 寄存器使用情况
 * @param node 结点
 */
static int bpf_node_asm_right_sub_expr(struct bpf_compilation_context *context,
                                       struct bpf_syntax_node         *node) {
    (void)context;
    assert(node->type == BPF_SYNTAX_NODE_RIGHT_SUB_EXPR);
    node->reg = node->right->reg;
    return 0;
}

static int bpf_node_asm(struct bpf_compilation_context *context, struct bpf_syntax_node *node) {
    switch (node->type) {
    case BPF_SYNTAX_NODE_COMPARISON:
        return bpf_node_asm_comparison(context, node);
    case BPF_SYNTAX_NODE_FIELD:
        return bpf_node_asm_field(context, node);
    case BPF_SYNTAX_NODE_CONSTANT:
        return bpf_node_asm_constant(context, node);
    case BPF_SYNTAX_NODE_JUMP_IF:
        return bpf_node_asm_jump_if(context, node);
    case BPF_SYNTAX_NODE_LABEL:
        return bpf_node_asm_label(context, node);
    case BPF_SYNTAX_NODE_RIGHT_SUB_EXPR:
        return bpf_node_asm_right_sub_expr(context, node);
    default:
        fprintf(stderr, "Invalid node\n");
        return -1;
    }
}

static int bpf_node_free(struct bpf_compilation_context *context, struct bpf_syntax_node *node) {
    if (!node) {
        return 0;  // 如果节点为空，直接返回
    }

    // 从待处理标签列表中移除
    if (node->type == BPF_SYNTAX_NODE_LABEL) {
        struct bpf_syntax_label_node *label = (struct bpf_syntax_label_node *)node;
        bpf_list_unlink(&label->list_hook);
    }

    // 释放当前节点的字符串表示
    free(node->str);
    free(node);
    return 0;
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

static void bpf_syntax_node_init(struct bpf_syntax_node   *node,
                                 enum bpf_syntax_node_type type,
                                 char                     *str) {
    node->type   = type;
    node->reg    = BPF_REGISTER_INVALID;
    node->pc     = -1;
    node->str    = str;
    node->parent = NULL;
    node->left   = NULL;
    node->right  = NULL;
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
    struct bpf_syntax_node *node = &field->node;             // 将基类指针指向子类
    bpf_syntax_node_init(node, BPF_SYNTAX_NODE_FIELD, str);  // 初始化节点
    field->attr = attr;                                      // 设置字段属性
    return node;
}

static struct bpf_syntax_node *bpf_syntax_label_node_new(uint32_t id) {
    // 生成标签名
    char buf[128];
    snprintf(buf, sizeof(buf), "label_%u", id);  // 生成标签

    // 分配标签节点
    struct bpf_syntax_label_node *label =
        (struct bpf_syntax_label_node *)malloc(sizeof(struct bpf_syntax_label_node));
    struct bpf_syntax_node *node = &label->node;
    bpf_syntax_node_init(node, BPF_SYNTAX_NODE_LABEL, strdup(buf));
    label->list_hook.prev = NULL;
    label->list_hook.next = NULL;
    label->target         = NULL;
    return node;
}

static struct bpf_syntax_node *bpf_syntax_node_generic_new(enum bpf_syntax_node_type type,
                                                           char                     *str) {
    struct bpf_syntax_node *node = (struct bpf_syntax_node *)malloc(sizeof(struct bpf_syntax_node));
    bpf_syntax_node_init(node, type, str);  // 初始化节点
    return node;
}

/**
 * @brief 查找语法树的最左结点
 */
static struct bpf_syntax_node *bpf_syntax_true_left_most(struct bpf_syntax_node *node) {
    // 查找左子树的最左结点
    while (node->left) {
        node = node->left;
    }

    return node;  // 返回最左结点
}

struct bpf_compilation_context *bpf_compilation_context_new() {
    struct bpf_compilation_context *context =
        (struct bpf_compilation_context *)malloc(sizeof(struct bpf_compilation_context));
    if (!context) {
        fprintf(stderr, "Failed to allocate memory for compilation context\n");
        return NULL;  // 内存分配失败
    }

    // 初始化寄存器使用情况
    context->reg_bitmap          = 0;
    context->pending_labels.prev = &context->pending_labels;
    context->pending_labels.next = &context->pending_labels;
    context->next_label_id       = 0;
    context->next_pc             = 0;
    return context;
}

void bpf_compilation_context_free(struct bpf_compilation_context *context) {
    if (!context) {
        return;  // 如果上下文为空，直接返回
    }

    free(context);  // 释放编译上下文
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
    bpf_list_append(&s_bpf_field_attr_list, &new_attr->list_hook);
    return 0;  // 成功注册字段
}

struct bpf_syntax_node *bpf_syntax_node_new(struct bpf_compilation_context *context,
                                            enum bpf_syntax_node_type       type,
                                            char                           *str) {
    switch (type) {
    case BPF_SYNTAX_NODE_FIELD:
        return bpf_syntax_field_node_new(str);
    case BPF_SYNTAX_NODE_LABEL:
        return bpf_syntax_label_node_new(bpf_asm_next_label_id(context));
    default:
        return bpf_syntax_node_generic_new(type, str);
    }
}

void bpf_syntax_node_free(struct bpf_compilation_context *context, struct bpf_syntax_node *node) {
    bpf_syntax_tree_post_order(node, bpf_node_free, context);
}

int bpf_syntax_tree_post_order(struct bpf_syntax_node *node,
                               int (*callback)(struct bpf_compilation_context *,
                                               struct bpf_syntax_node *),
                               struct bpf_compilation_context *context) {
    if (!node) {
        return 0;
    }

    if (bpf_syntax_tree_post_order(node->left, callback, context) < 0) {
        return -1;
    }

    if (bpf_syntax_tree_post_order(node->right, callback, context) < 0) {
        return -1;
    }

    return callback(context, node);
}

void bpf_asm(struct bpf_compilation_context *context, struct bpf_syntax_node *node) {
    // R0 为传的第一个参数，默认有一个参数
    context->reg_bitmap |= (1ULL << (BPF_REGISTER_R0 - BPF_REGISTER_R0));  // 标记 R0 为已使用

    // 后序遍历语法树，生成 BPF 汇编代码
    bpf_syntax_tree_post_order(node, bpf_node_asm, context);

    // 最终将结果寄存器的值移动到 R0，然后返回
    printf("%04hx: %-8s %s -> R0\n", bpf_asm_next_pc(context), "mov", bpf_register_name(node->reg));
    printf("%04hx: %-8s\n", bpf_asm_next_pc(context), "ret");

    // 打印 label 的跳转目标
    for (struct bpf_list_node *node = context->pending_labels.next;
         node != &context->pending_labels;
         node = node->next) {
        struct bpf_syntax_label_node *label =
            bpf_container_of(node, struct bpf_syntax_label_node, list_hook);
        assert(label->node.type == BPF_SYNTAX_NODE_LABEL);
        assert(label->target);
        struct bpf_syntax_node *left_most = bpf_syntax_true_left_most(label->target);
        assert(left_most);
        printf("%-16s %04hx\n", label->node.str, left_most->pc);
    }
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