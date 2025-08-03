#include "bpf_ast.h"

#include <alloca.h>
#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "bpf_instrin.h"

#define bpf_container_of(ptr, type, member) ((type *)((char *)(ptr)-offsetof(type, member)))

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
struct bpf_ast_field_attr {
    struct bpf_list_node list_hook;  ///< 链表钩子，用于链表管理
    char                *name;       ///< 字段名称
    uint8_t              argn;       ///< 字段地址所在参数编号
    uint8_t              size;       ///< 字段大小
    uint16_t             offset;     ///< 字段相对于参数的偏移量
};

/**
 * @brief 字段节点结构体
 */
struct bpf_ast_field_node {
    struct bpf_ast_node              node;  ///< 基类
    const struct bpf_ast_field_attr *attr;  ///< 字段属性
};

/**
 * @brief 条件语句节点结构体
 */
struct bpf_ast_if_node {
    struct bpf_ast_node  node;          ///< 基类
    struct bpf_ast_node *true_branch;   ///< 真分支
    struct bpf_ast_node *false_branch;  ///< 假分支
};

/**
 * @brief 编译上下文结构体
 */
struct bpf_ast_context {
    uint64_t  reg_bitmap;      ///< 寄存器分配位图
    uint16_t  next_label_id;   ///< 下一个标签 ID，用于生成唯一标签名
    uint16_t  next_pc;         ///< 下一个程序计数器
    uint16_t  instr_capacity;  ///< 指令容量
    uint32_t *instrs;          ///< 指令数组
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

/**
 * @brief 分配一个未使用的寄存器
 *
 * @param reg_usage 寄存器使用情况
 * @return int 返回分配的寄存器编号，-1 表示没有可用寄存器
 */
static int bpf_asm_register_alloc(struct bpf_ast_context *context) {
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
static void bpf_asm_register_free(struct bpf_ast_context *context, int reg) {
    assert(reg >= BPF_REGISTER_R0 && reg <= BPF_REGISTER_R7);
    uint64_t mask = 1ULL << (reg - BPF_REGISTER_R0);
    context->reg_bitmap &= ~mask;  // 清除寄存器使用标记
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
 * @brief 扩展指令数组的容量
 *
 * @param context 编译上下文
 * @return 成功时返回 0，失败时返回 -1
 */
static int bpf_asm_expand_instrs(struct bpf_ast_context *context) {
    if (context->next_pc >= UINT16_MAX) {
        fprintf(stderr, "Instruction length exceeds maximum limit\n");
        return -1;  // 指令长度超过最大限制
    }

    // 扩展指令数组的容量
    if (context->next_pc >= context->instr_capacity) {
        size_t    new_capacity = context->instr_capacity ? context->instr_capacity * 2 : 16;
        uint32_t *new_instrs   = realloc(context->instrs, new_capacity * sizeof(uint32_t));
        if (!new_instrs) {
            fprintf(stderr, "Failed to allocate memory for instructions\n");
            return -1;  // 内存分配失败
        }

        context->instrs         = new_instrs;
        context->instr_capacity = new_capacity;
    }

    return 0;  // 成功扩展指令数组
}

/**
 * @brief 将一条指令追加到编译上下文的指令数组中
 *
 * @param context 编译上下文
 * @param instr 要追加的指令
 * @return int 成功时返回指令的指令计数器位置；失败时返回 -1
 */
static int bpf_asm_append_instr(struct bpf_ast_context *context, uint32_t instr) {
    // 扩展指令数组容量
    if (bpf_asm_expand_instrs(context) < 0) {
        return -1;  // 扩展失败
    }

    // 将指令添加到数组中
    uint16_t pc = context->next_pc++;
    assert(pc < context->next_pc);  // 确保程序计数器不会溢出
    context->instrs[pc] = instr;
    return pc;
}

/**
 * @brief 将寄存器编号转换为寄存器 ID
 */
static inline int bpf_asm_register_id(int reg) {
    return reg - BPF_REGISTER_R0;  // 将寄存器编号转换为 ID
}

/**
 * @brief 生成比较操作的 BPF 汇编代码
 *
 * @param reg_usage 寄存器使用情况
 * @param node 结点
 * @return 成功时返回 0，失败时返回 -1
 */
static int bpf_node_asm_comparison(struct bpf_ast_context *context, struct bpf_ast_node *node) {
    assert(node->type == BPF_AST_NODE_COMPARISON);

    // 添加指令到编译上下文
    uint32_t cmp_instr = bpf_instrin_cmp(bpf_asm_register_id(node->left->reg),
                                         bpf_asm_register_id(node->right->reg));
    node->pc           = bpf_asm_append_instr(context, cmp_instr);
    node->instr_len    = 1;
    node->reg          = BPF_REGISTER_LCR;

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
static int bpf_node_asm_field(struct bpf_ast_context *context, struct bpf_ast_node *node) {
    assert(node->type == BPF_AST_NODE_FIELD);

    // 从 reg_usage 找出可用的寄存器
    int reg = bpf_asm_register_alloc(context);
    if (reg < 0) {
        fprintf(stderr, "No available registers for field: %s\n", node->str);
        return -1;
    }

    struct bpf_ast_field_node       *field = (struct bpf_ast_field_node *)node;
    const struct bpf_ast_field_attr *attr  = field->attr;
    assert(attr && ((attr->size - 1) & attr->size) == 0 && attr->size <= 8);

    // 添加指令到编译上下文
    uint32_t load_instr = bpf_instrin_load(__builtin_ctz(attr->size),
                                           bpf_asm_register_id(reg),
                                           bpf_asm_register_id(bpf_asm_argn2reg(attr->argn)),
                                           attr->offset);
    node->pc            = bpf_asm_append_instr(context, load_instr);
    node->instr_len     = 1;
    node->reg           = reg;
    return 0;
}

/**
 * @brief 生成加载常量的 BPF 汇编代码
 *
 * @param reg_usage 寄存器使用情况
 * @param constant 常量值
 * @return 成功时返回 0，失败时返回 -1
 */
static int bpf_node_asm_constant(struct bpf_ast_context *context, struct bpf_ast_node *node) {
    // 从 reg_usage 找出可用的寄存器
    int reg = bpf_asm_register_alloc(context);
    if (reg < 0) {
        fprintf(stderr, "No available registers for constant: %s\n", node->str);
        return -1;
    }

    // TODO: 通过另一个操作数据来判断数据类型

    // 添加指令到编译上下文
    uint32_t set_instr = bpf_instrin_set(0, bpf_asm_register_id(reg), (uint16_t)atoi(node->str));
    node->pc           = bpf_asm_append_instr(context, set_instr);
    node->instr_len    = 1;
    node->reg          = reg;
    return 0;
}

/**
 * @brief 向上查找第一个不是指定类型的父节点
 *
 * @param node 当前节点
 * @param type 要查找的节点类型
 * @return 返回找到的父节点，如果没有找到则返回 NULL
 */
static struct bpf_ast_node *bpf_ast_find_parent(struct bpf_ast_node   *node,
                                                enum bpf_ast_node_type type) {
    node = node->parent;
    while (node && node->type == type) {
        node = node->parent;  // 向上查找父节点
    }

    return node;  // 没有找到符合条件的父节点
}

/**
 * @brief 生成条件语句的 BPF 汇编代码
 *
 * @param context 编译上下文
 * @param node 结点
 * @return int 成功时返回 0，失败时返回 -1
 */
static int bpf_node_asm_if(struct bpf_ast_context *context, struct bpf_ast_node *node) {
    assert(node->type == BPF_AST_NODE_IF);

    struct bpf_ast_node *left = node->left;
    const char          *cmp_op;

    // 获取比较操作符
    if (left->type == BPF_AST_NODE_COMPARISON) {
        cmp_op = left->str;
    } else if (left->type == BPF_AST_NODE_IF || BPF_AST_NODE_IF_FALSE) {
        assert(left->right && left->right->type == BPF_AST_NODE_COMPARISON);
        cmp_op = left->right->str;
    } else {
        fprintf(stderr, "Unsupported left node type for IF: %d\n", left->type);
        return -1;  // 不支持的左子结点类型
    }

    // 根据比较操作符生成相应的跳转指令
    uint32_t jmp_instr;
    if (strcmp(cmp_op, "==") == 0) {
        jmp_instr = bpf_instrin_jne(0);
    } else if (strcmp(cmp_op, "!=") == 0) {
        jmp_instr = bpf_instrin_je(0);
    } else if (strcmp(cmp_op, "<") == 0) {
        jmp_instr = bpf_instrin_jnl(0);
    } else if (strcmp(cmp_op, "<=") == 0) {
        jmp_instr = bpf_instrin_jg(0);
    } else if (strcmp(cmp_op, ">") == 0) {
        jmp_instr = bpf_instrin_jng(0);
    } else if (strcmp(cmp_op, ">=") == 0) {
        jmp_instr = bpf_instrin_jl(0);
    } else {
        fprintf(stderr, "Unsupported comparison operator: %s\n", left->str);
        return -1;
    }

    // 添加跳转指令到编译上下文
    node->pc        = bpf_asm_append_instr(context, jmp_instr);
    node->instr_len = 1;

    // 设置 true_branch 和 false_branch
    struct bpf_ast_if_node *if_node = (struct bpf_ast_if_node *)node;
    struct bpf_ast_node    *p       = bpf_ast_find_parent(node, BPF_AST_NODE_IF);
    if_node->false_branch           = p ? p->right : NULL;
    if_node->true_branch            = node->right;
    assert(!p || p->type == BPF_AST_NODE_IF_FALSE);
    return 0;
}

/**
 * @brief 生成条件语句的否定 BPF 汇编代码
 *
 * @param context 编译上下文
 * @param node 结点
 * @return int 成功时返回 0，失败时返回 -1
 */
static int bpf_node_asm_if_false(struct bpf_ast_context *context, struct bpf_ast_node *node) {
    assert(node->type == BPF_AST_NODE_IF_FALSE);

    struct bpf_ast_node *left = node->left;
    const char          *cmp_op;

    // 获取比较操作符
    if (left->type == BPF_AST_NODE_COMPARISON) {
        cmp_op = left->str;
    } else if (left->type == BPF_AST_NODE_IF || BPF_AST_NODE_IF_FALSE) {
        assert(left->right && left->right->type == BPF_AST_NODE_COMPARISON);
        cmp_op = left->right->str;
    } else {
        fprintf(stderr, "Unsupported left node type for IF_FALSE: %d\n", left->type);
        return -1;  // 不支持的左子结点类型
    }

    // 根据比较操作符生成相应的跳转指令
    uint32_t jmp_instr;
    if (strcmp(cmp_op, "==") == 0) {
        jmp_instr = bpf_instrin_je(0);
    } else if (strcmp(cmp_op, "!=") == 0) {
        jmp_instr = bpf_instrin_jne(0);
    } else if (strcmp(cmp_op, "<") == 0) {
        jmp_instr = bpf_instrin_jl(0);
    } else if (strcmp(cmp_op, "<=") == 0) {
        jmp_instr = bpf_instrin_jng(0);
    } else if (strcmp(cmp_op, ">") == 0) {
        jmp_instr = bpf_instrin_jg(0);
    } else if (strcmp(cmp_op, ">=") == 0) {
        jmp_instr = bpf_instrin_jnl(0);
    } else {
        fprintf(stderr, "Unsupported comparison operator: %s\n", left->str);
        return -1;  // 不支持的比较运算符
    }

    // 添加跳转指令到编译上下文
    node->pc        = bpf_asm_append_instr(context, jmp_instr);
    node->instr_len = 1;

    // 设置 true_branch 和 false_branch
    struct bpf_ast_if_node *if_node = (struct bpf_ast_if_node *)node;
    struct bpf_ast_node    *p       = bpf_ast_find_parent(node, BPF_AST_NODE_IF_FALSE);
    if_node->true_branch            = p ? p->right : NULL;
    if_node->false_branch           = node->right;
    assert(!p || p->type == BPF_AST_NODE_IF);
    return 0;
}

/**
 * @brief 生成 BPF 汇编代码
 *
 * @param context 编译上下文
 * @param node 结点
 * @return int 成功时返回 0，失败时返回 -1
 */
static int bpf_asm_gen(struct bpf_ast_context *context, struct bpf_ast_node *node) {
    switch (node->type) {
    case BPF_AST_NODE_COMPARISON:
        if (bpf_asm_gen(context, node->left) < 0) {
            return -1;  // 左子结点生成失败
        }

        if (bpf_asm_gen(context, node->right) < 0) {
            return -1;  // 右子结点生成失败
        }

        return bpf_node_asm_comparison(context, node);  // 生成比较操作的 BPF 汇编代码

    case BPF_AST_NODE_FIELD:
        assert(!node->left && !node->right);       // 字段节点没有子结点
        return bpf_node_asm_field(context, node);  // 生成加载字段的

    case BPF_AST_NODE_CONSTANT:
        assert(!node->left && !node->right);          // 常量节点没有子结点
        return bpf_node_asm_constant(context, node);  // 生成加载常量的 BPF 汇编代码

    case BPF_AST_NODE_IF:
        assert(node->left && node->right);  // 条件语句节点必须有
        if (bpf_asm_gen(context, node->left) < 0) {
            return -1;  // 左子结点生成失败
        }

        if (bpf_node_asm_if(context, node) < 0) {
            return -1;  // 条件语句生成失败
        }

        if (bpf_asm_gen(context, node->right) < 0) {
            return -1;  // 右子结点生成失败
        }

        return 0;  // 成功生成条件语句

    case BPF_AST_NODE_IF_FALSE:
        assert(node->left && node->right);  // 条件语句的否定节点必须有
        if (bpf_asm_gen(context, node->left) < 0) {
            return -1;  // 左子结点生成失败
        }

        if (bpf_node_asm_if_false(context, node) < 0) {
            return -1;  // 条件语句生成失败
        }

        if (bpf_asm_gen(context, node->right) < 0) {
            return -1;  // 右子结点生成失败
        }

        return 0;  // 成功生成条件语句的否定

    default:
        fprintf(stderr, "Unsupported node type: %d\n", node->type);
        return -1;  // 不支持的节点类型
    }
}

/**
 * @brief 释放单个语法树结点及其字符串表示
 *
 * @param arg 未使用的参数
 * @param node 结点
 * @return int 成功时返回 0，失败时返回 -1
 */
static int bpf_ast_node_free_single(void *arg, struct bpf_ast_node *node) {
    if (!node) {
        return 0;  // 如果节点为空，直接返回
    }

    // 释放当前节点的字符串表示
    free(node->str);
    free(node);
    return 0;
}

/**
 * @brief 查找语法树的最左结点
 */
static struct bpf_ast_node *bpf_ast_true_left_most(struct bpf_ast_node *node) {
    // 查找左子树的最左结点
    while (node->left) {
        node = node->left;
    }

    return node;  // 返回最左结点
}

/**
 * @brief 设置跳转指令的偏移量
 *
 * @param instrs 要修改的指令
 * @param offset 新的跳转偏移量
 */
static void bpf_asm_set_jmp_offset(uint32_t *instrs, uint16_t offset) {
    struct bpf_instrin_jmp *jmp_instr = (struct bpf_instrin_jmp *)instrs;
    assert(BPF_INSTRIN_JMP <= jmp_instr->opcode && jmp_instr->opcode <= BPF_INSTRIN_JNL);
    jmp_instr->offset = offset;
}

/**
 * @brief 修正 if 语句的跳转指令
 *
 * @param arg 编译上下文
 * @param node 结点
 * @return int 成功时返回 0，失败时返回 -1
 */
static int bpf_ast_node_fix_if_jump(void *arg, struct bpf_ast_node *node) {
    if (!node) {
        return 0;  // 如果节点为空或不是条件语句节点，直接返回
    }

    struct bpf_ast_context *context = (struct bpf_ast_context *)arg;

    if (node->type == BPF_AST_NODE_IF) {
        // 获取 false_branch 的程序计数器
        struct bpf_ast_if_node *if_node = (struct bpf_ast_if_node *)node;
        if (if_node->false_branch) {
            // 修正 false_branch 的跳转偏移量
            assert(if_node->false_branch->type == BPF_AST_NODE_COMPARISON);
            struct bpf_ast_node *left_most = bpf_ast_true_left_most(if_node->false_branch);
            uint32_t             offset    = left_most->pc - node->pc - 1;
            bpf_asm_set_jmp_offset(context->instrs + node->pc, offset);
        } else {
            // 直接跳转到程序末尾
            uint32_t offset = context->next_pc - node->pc - 3;
            bpf_asm_set_jmp_offset(context->instrs + node->pc, offset);
        }
    } else if (node->type == BPF_AST_NODE_IF_FALSE) {
        // 获取 true_branch 的程序计数器
        struct bpf_ast_if_node *if_node = (struct bpf_ast_if_node *)node;
        if (if_node->true_branch) {
            // 修正 true_branch 的跳转偏移量
            assert(if_node->true_branch->type == BPF_AST_NODE_COMPARISON);
            struct bpf_ast_node *left_most = bpf_ast_true_left_most(if_node->true_branch);
            uint32_t             offset    = left_most->pc - node->pc - 1;
            bpf_asm_set_jmp_offset(context->instrs + node->pc, offset);
        } else {
            // 直接跳转到程序末尾
            uint32_t offset = context->next_pc - node->pc - 5;
            bpf_asm_set_jmp_offset(context->instrs + node->pc, offset);
        }
    }

    return 0;
}

static const struct bpf_ast_field_attr *bpf_field_attr_find(const char *name) {
    // 在全局字段链表中查找字段属性
    for (struct bpf_list_node *node = s_bpf_field_attr_list.next; node != &s_bpf_field_attr_list;
         node                       = node->next) {
        struct bpf_ast_field_attr *attr = (struct bpf_ast_field_attr *)node;
        if (strcmp(attr->name, name) == 0) {
            return attr;  // 找到匹配的字段属性
        }
    }

    return NULL;  // 未找到字段属性
}

static void bpf_ast_node_init(struct bpf_ast_node *node, enum bpf_ast_node_type type, char *str) {
    node->type      = type;
    node->reg       = BPF_REGISTER_INVALID;
    node->instr_len = 0;
    node->pc        = -1;
    node->str       = str;
    node->parent    = NULL;
    node->left      = NULL;
    node->right     = NULL;
}

static struct bpf_ast_node *bpf_ast_field_node_new(char *str) {
    // 查找全局字段链表中是否已存在同名字段
    const struct bpf_ast_field_attr *attr = bpf_field_attr_find(str);
    if (!attr) {
        fprintf(stderr, "Field %s not registered\n", str);
        return NULL;  // 字段未注册
    }

    struct bpf_ast_field_node *p =
        (struct bpf_ast_field_node *)malloc(sizeof(struct bpf_ast_field_node));
    struct bpf_ast_node *node = &p->node;              // 将基类指针指向子类
    bpf_ast_node_init(node, BPF_AST_NODE_FIELD, str);  // 初始化节点
    p->attr = attr;                                    // 设置字段属性
    return node;
}

static struct bpf_ast_node *bpf_ast_if_node_new(enum bpf_ast_node_type type, char *str) {
    struct bpf_ast_if_node *p    = (struct bpf_ast_if_node *)malloc(sizeof(struct bpf_ast_if_node));
    struct bpf_ast_node    *node = &p->node;  // 将基类指针指向子类
    bpf_ast_node_init(node, type, str);       // 初始化节点
    return node;
}

static struct bpf_ast_node *bpf_ast_node_generic_new(enum bpf_ast_node_type type, char *str) {
    struct bpf_ast_node *node = (struct bpf_ast_node *)malloc(sizeof(struct bpf_ast_node));
    bpf_ast_node_init(node, type, str);  // 初始化节点
    return node;
}

struct bpf_ast_context *bpf_ast_context_new() {
    struct bpf_ast_context *context =
        (struct bpf_ast_context *)malloc(sizeof(struct bpf_ast_context));
    if (!context) {
        fprintf(stderr, "Failed to allocate memory for ast context\n");
        return NULL;  // 内存分配失败
    }

    // 初始化寄存器使用情况
    context->reg_bitmap     = 0;
    context->next_label_id  = 0;
    context->next_pc        = 0;
    context->instr_capacity = 0;
    context->instrs         = NULL;
    return context;
}

void bpf_ast_context_free(struct bpf_ast_context *context) {
    if (!context) {
        return;  // 如果上下文为空，直接返回
    }

    if (context->instrs) {
        free(context->instrs);  // 释放指令数组
    }

    free(context);  // 释放编译上下文
}

int bpf_ast_register_field(const char *name, uint8_t argn, uint8_t size, uint16_t offset) {
    // 检查 name 参数有效性
    if (!name || strlen(name) == 0) {
        fprintf(stderr, "Field name cannot be empty\n");
        return -1;  // 字段名称不能为空
    }

    // 检查 size 参数有效性
    if (size != 1 && size != 2 && size != 4 && size != 8) {
        fprintf(stderr, "Field size must be 1, 2, 4, or 8 bytes\n");
        return -1;  // 字段大小不合法
    }

    // 在全局字段链表中查找是否已存在同名字段
    if (bpf_field_attr_find(name)) {
        fprintf(stderr, "Field %s already registered\n", name);
        return -1;  // 字段已存在
    }

    // 创建新的字段属性
    struct bpf_ast_field_attr *new_attr =
        (struct bpf_ast_field_attr *)malloc(sizeof(struct bpf_ast_field_attr));
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

struct bpf_ast_node *bpf_ast_node_new(enum bpf_ast_node_type type, char *str) {
    switch (type) {
    case BPF_AST_NODE_FIELD:
        return bpf_ast_field_node_new(str);
    case BPF_AST_NODE_IF:
    case BPF_AST_NODE_IF_FALSE:
        return bpf_ast_if_node_new(type, str);
        break;
    default:
        return bpf_ast_node_generic_new(type, str);
    }
}

void bpf_ast_node_free(struct bpf_ast_node *node) {
    bpf_ast_tree_post_order(node, bpf_ast_node_free_single, NULL);
}

int bpf_ast_tree_post_order(struct bpf_ast_node *node,
                            int (*callback)(void*, struct bpf_ast_node *),
                            void *arg) {
    if (!node) {
        return 0;
    }

    if (bpf_ast_tree_post_order(node->left, callback, arg) < 0) {
        return -1;
    }

    if (bpf_ast_tree_post_order(node->right, callback, arg) < 0) {
        return -1;
    }

    return callback(arg, node);
}

int bpf_ast_assemble(struct bpf_ast_context *context, struct bpf_ast_node *node) {
    // R0 为传的第一个参数，默认有一个参数
    context->reg_bitmap |= (1ULL << (BPF_REGISTER_R0 - BPF_REGISTER_R0));  // 标记 R0 为已使用

    // 生成 BPF 汇编代码
    if (bpf_asm_gen(context, node) < 0) {
        fprintf(stderr, "Failed to generate BPF assembly code\n");
        return -1;  // 生成失败
    }

    // 获取比较操作符
    const char *cmp_op;
    if (node->type == BPF_AST_NODE_COMPARISON) {
        cmp_op = node->str;  // 获取比较操作符
    } else if (node->type == BPF_AST_NODE_IF || node->type == BPF_AST_NODE_IF_FALSE) {
        assert(node->right && node->right->type == BPF_AST_NODE_COMPARISON);
        cmp_op = node->right->str;  // 获取左子结点的比较操作符
    } else {
        fprintf(stderr, "Unsupported node type for comparison: %d\n", node->type);
        return -1;  // 不支持的节点类型
    }

    // 根据比较操作符生成相应的跳转指令
    if (strcmp(cmp_op, "==") == 0) {
        uint32_t jne_instr = bpf_instrin_jne(2);  // 跳转到 false 分支
        bpf_asm_append_instr(context, jne_instr);
    } else if (strcmp(cmp_op, "!=") == 0) {
        uint32_t je_instr = bpf_instrin_je(2);  // 跳转到 false 分支
        bpf_asm_append_instr(context, je_instr);
    } else {
        fprintf(stderr, "Unsupported comparison operator: %s\n", node->str);
        return -1;  // 不支持的比较运算符
    }

    // 创建返回指令
    uint32_t ret_instr = bpf_instrin_ret();

    // 最后的 true 分支指令
    uint32_t set_true_instr = bpf_instrin_set(0, bpf_asm_register_id(BPF_REGISTER_R0), 1);
    bpf_asm_append_instr(context, set_true_instr);
    bpf_asm_append_instr(context, ret_instr);

    // 最后的 false 分支指令
    uint32_t set_false_instr = bpf_instrin_set(0, bpf_asm_register_id(BPF_REGISTER_R0), 0);
    bpf_asm_append_instr(context, set_false_instr);
    bpf_asm_append_instr(context, ret_instr);

    // 遍历语法树，修正条件语句的跳转指令
    if (bpf_ast_tree_post_order(node, bpf_ast_node_fix_if_jump, context) < 0) {
        fprintf(stderr, "Failed to fix IF jump instructions\n");
        return -1;  // 修正跳转指令失败
    }

    return 0;
}

uint16_t bpf_ast_fetch_instrs(struct bpf_ast_context *context, uint32_t **instrs) {
    assert(context && instrs);
    *instrs              = context->instrs;
    uint16_t instr_count = context->next_pc;
    context->instrs      = NULL;
    context->next_pc     = 0;
    return instr_count;
}

/**
 * @brief 清理函数
 */
__attribute__((destructor)) static void bpf_ast_cleanup() {
    // 清理全局字段链表
    struct bpf_list_node *node = s_bpf_field_attr_list.next;
    while (node != &s_bpf_field_attr_list) {
        struct bpf_ast_field_attr *attr = (struct bpf_ast_field_attr *)node;
        node                            = node->next;
        free(attr->name);  // 释放字段名称
        free(attr);        // 释放字段属性结构体
    }
}