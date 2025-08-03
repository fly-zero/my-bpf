#include "bpf_program.h"

#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_ast.h"
#include "bpf_instrin.h"

/**
 * @brief bpf 程序
 *
 * @note bpf 程序是一个简单的虚拟机程序，具有如下特点：
 *      - 16 个 64 位寄存器
 *      - 32-bit 的固定长度指令
 *      - regs[0] 作为返回值
 *      - regs[1 ~ 4] 作为参数寄存器
 *      - 最大支持 2^16 条指令
 */
struct pbf_program {
    const uint32_t *instrs;        ///< 程序指令开始地址
    uint16_t        instrs_count;  ///< 指令数量
    uint16_t        pc;            ///< 程序计数器
    int64_t         lcr;           ///< 上一次比较的结果
    uint64_t        regs[16];      ///< 寄存器
};

extern struct bpf_ast_node *bpf_compile(const char *expr);

static int s_bpf_errno = BPF_ERROR_OK;

static const char *s_bpf_errno_str[] = {
    [BPF_ERROR_OK]                  = "Success",
    [BPF_ERROR_INVALID_ARGUMENT]    = "Invalid argument",
    [BPF_ERROR_OUT_OF_MEMORY]       = "Out of memory",
    [BPF_ERROR_SYNTAX]              = "Syntax error",
    [BPF_ERROR_INVALID_INSTRUCTION] = "Invalid instruction",
};

static inline void bpf_instrin_execute_load(struct pbf_program *program, const uint32_t *instr) {
    uint64_t                      *regs = program->regs;
    const struct bpf_instrin_load *load = (const struct bpf_instrin_load *)instr;
    memcpy(&regs[load->dst], (uint8_t *)regs[load->src] + load->offset, 1 << load->width);
}

static inline void bpf_instrin_execute_set(struct pbf_program *program, const uint32_t *instr) {
    uint64_t                     *regs = program->regs;
    const struct bpf_instrin_set *set  = (const struct bpf_instrin_set *)instr;
    regs[set->dst]                     = regs[set->dst] | (set->value << set->offset);
}

static inline void bpf_instrin_execute_cmp(struct pbf_program *program, const uint32_t *instr) {
    uint64_t                     *regs = program->regs;
    const struct bpf_instrin_cmp *cmp  = (const struct bpf_instrin_cmp *)instr;
    program->lcr                       = regs[cmp->lr] - regs[cmp->rr];
}

static inline void bpf_instrin_execute_jmp(struct pbf_program *program, const uint32_t *instr) {
    const struct bpf_instrin_jmp *jmp = (const struct bpf_instrin_jmp *)instr;
    program->pc += jmp->offset;
}

static inline void bpf_instrin_execute_je(struct pbf_program *program, const uint32_t *instr) {
    const struct bpf_instrin_jmp *cj = (const struct bpf_instrin_jmp *)instr;
    if (program->lcr == 0) {
        program->pc += cj->offset;
    }
}

static inline void bpf_instrin_execute_jne(struct pbf_program *program, const uint32_t *instr) {
    const struct bpf_instrin_jmp *cj = (const struct bpf_instrin_jmp *)instr;
    if (program->lcr != 0) {
        program->pc += cj->offset;
    }
}

static inline void bpf_instrin_execute_jg(struct pbf_program *program, const uint32_t *instr) {
    const struct bpf_instrin_jmp *cj = (const struct bpf_instrin_jmp *)&instr;
    if (program->lcr > 0) {
        program->pc += cj->offset;
    }
}

static inline void bpf_instrin_execute_jl(struct pbf_program *program, const uint32_t *instr) {
    const struct bpf_instrin_jmp *cj = (const struct bpf_instrin_jmp *)&instr;
    if (program->lcr < 0) {
        program->pc += cj->offset;
    }
}

static inline void bpf_instrin_execute_jng(struct pbf_program *program, const uint32_t *instr) {
    const struct bpf_instrin_jmp *cj = (const struct bpf_instrin_jmp *)&instr;
    if (program->lcr <= 0) {
        program->pc += cj->offset;
    }
}

static inline void bpf_instrin_execute_jnl(struct pbf_program *program, const uint32_t *instr) {
    const struct bpf_instrin_jmp *cj = (const struct bpf_instrin_jmp *)&instr;
    if (program->lcr >= 0) {
        program->pc += cj->offset;
    }
}

static inline void bpf_instrin_execute_ret(struct pbf_program *program, const uint32_t *instr) {
    // 返回指令不需要做任何操作，直接返回即可
    (void)instr;                          // 避免未使用参数的警告
    program->pc = program->instrs_count;  // 设置 pc 到程序末尾，表示执行结束
}

/**
 * @brief 检查指令是否为 load 指令
 */
static int bpf_instrin_is_load(uint32_t instr) {
    return (instr & BPF_INSTRIN_OPCODE_MASK) == BPF_INSTRIN_LOAD;
}

/**
 * @brief 检查指令是否为 set 指令
 */
static int bpf_instrin_is_set(uint32_t instr) {
    return (instr & BPF_INSTRIN_OPCODE_MASK) == BPF_INSTRIN_SET;
}

/**
 * @brief 检查指令是否为跳转指令
 */
static int bpf_instrin_is_jmp(uint32_t instr) {
    uint32_t opcode = instr & BPF_INSTRIN_OPCODE_MASK;
    return BPF_INSTRIN_JMP <= opcode && opcode <= BPF_INSTRIN_JNL;
};

/**
 * @brief 将寄存器编号转换为寄存器 ID
 */
static inline int bpf_asm_register_id(int reg) {
    return reg - BPF_REGISTER_R0;  // 将寄存器编号转换为 ID
}

/**
 * @brief 检查寄存器在指定的指令范围内是否被修改
 *
 * @param instrs 指令数组
 * @param reg 寄存器编号
 * @param start_pc 起始程序计数器
 * @param end_pc 结束程序计数器
 * @return int
 */
static int bpf_asm_is_register_modified_between(const uint32_t *instrs,
                                                uint8_t         reg,
                                                uint16_t        bgn_pc,
                                                uint16_t        end_pc) {
    // 检查在 start_pc 和 end_pc 之间是否有修改 reg 的指令
    for (uint16_t pc = bgn_pc; pc < end_pc; ++pc) {
        uint32_t instr = instrs[pc];
        if (bpf_instrin_is_load(instr)) {
            struct bpf_instrin_load *load_instr = (struct bpf_instrin_load *)&instr;
            if (load_instr->dst == bpf_asm_register_id(reg)) {
                return 1;  // 找到修改 reg 的指令
            }
        } else if (bpf_instrin_is_set(instr)) {
            struct bpf_instrin_set *set_instr = (struct bpf_instrin_set *)&instr;
            if (set_instr->dst == bpf_asm_register_id(reg)) {
                return 1;  // 找到修改 reg 的指令
            }
        }
    }

    return 0;  // 没有找到修改 reg 的指令
}

/**
 * @brief 在指令索引数组 \b last_instr_pc 中查找与 \b target 相同的指令
 *
 * @param instrs 指令数组
 * @param count 指令数组的长度
 * @param last_load_idx 指令索引数组
 * @param last_load_cnt 指令索引数组的长度
 * @param target 要查找的目标指令
 * @return uint32_t 如果找到相同的指令，返回指令索引值；否则返回 UINT16_MAX
 */
static uint32_t bpf_asm_find_same_instr(const uint32_t *instrs,
                                        uint16_t        count,
                                        const uint16_t *last_load_idx,
                                        uint16_t        last_load_cnt,
                                        uint32_t        target) {
    for (uint32_t i = 0; i < last_load_cnt; ++i) {
        uint16_t pc = last_load_idx[i];
        assert(pc < count);
        if (instrs[pc] == target) {
            return i;
        }
    }

    return UINT32_MAX;
}

/**
 * @brief 消除冗余的加载指令
 *
 * @param context 编译上下文
 * @return uint16_t 返回新的指令数量
 */
static uint16_t bpf_asm_remove_redundant_loads(uint32_t *instrs, uint16_t count) {
    uint16_t *last_load_idx   = alloca(count * sizeof(uint16_t));
    uint16_t  last_load_cnt   = 0;
    int       redundant_loads = 0;

    // 找到冗余的加载指令
    for (uint16_t pc = 0; pc < count; pc++) {
        uint32_t instr = instrs[pc];
        if (bpf_instrin_is_load(instr)) {
            // 检查是否是冗余的加载指令
            uint32_t i =
                bpf_asm_find_same_instr(instrs, count, last_load_idx, last_load_cnt, instr);
            if (i < last_load_cnt) {  // 找到冗余的加载指令
                uint16_t                 last_load_pc = last_load_idx[i];
                struct bpf_instrin_load *load_instr   = (struct bpf_instrin_load *)&instr;
                if (!bpf_asm_is_register_modified_between(
                        instrs, load_instr->dst, last_load_pc + 1, pc)) {
                    instrs[pc] = -1u;  // 标记为冗余指令
                    ++redundant_loads;
                } else {
                    // 如果有修改，则更新 last_load_idx
                    last_load_idx[i] = pc;  // 更新最后一个加载指令位置
                }
            } else {                                  // 没有找到冗余的加载指令
                last_load_idx[last_load_cnt++] = pc;  // 记录加载指令位置
            }
        }
    }

    // 移除冗余的加载指令
    for (int pc = count - 1; pc >= 0 && redundant_loads >= 0; --pc) {
        if (instrs[pc] == -1u) {  // 如果是冗余指令
            // 将 [0, pc) 之间的跳转目的大于 pc 的跳转指令 offset 减少 1
            for (uint16_t i = 0; i < pc; ++i) {
                if (bpf_instrin_is_jmp(instrs[i])) {
                    struct bpf_instrin_jmp *jmp_instr = (struct bpf_instrin_jmp *)&instrs[i];
                    if (i + jmp_instr->offset > pc) {
                        --jmp_instr->offset;  // 减少跳转偏移量
                    }
                }
            }

            // 将 [pc + 1, next_pc) 之间的指令向前移动一位
            memmove(instrs + pc, instrs + pc + 1, (count - pc - 1) * sizeof(uint32_t));

            // 减少指令计数器
            --count;
        }
    }

    return count;
}

int bpf_optimize(uint32_t *instrs, uint16_t *count) {
    // 移除冗余的加载指令
    *count = bpf_asm_remove_redundant_loads(instrs, *count);

    return 0;
}

int bpf_register_field(const char *name, uint8_t argn, uint8_t size, uint16_t offset) {
    return bpf_ast_register_field(name, argn, size, offset);
}

struct pbf_program *bpf_assemble(const char *expr) {
    struct bpf_ast_node    *ast     = NULL;
    struct bpf_ast_context *context = NULL;
    uint32_t               *instrs  = NULL;
    uint16_t                count   = 0;

    if (!expr) {
        return NULL;
    }

    // 创建语法树
    if (!(ast = bpf_compile(expr))) {
        goto error_exit;  // 编译失败
    }

    // 创建编译上下文
    if (!(context = bpf_ast_context_new())) {
        goto error_exit;  // 编译失败
    }

    // 生成 BPF 汇编
    if (bpf_ast_assemble(context, ast) < 0) {
        goto error_exit;  // 汇编失败
    };

    // 获取指令数组
    count = bpf_ast_fetch_instrs(context, &instrs);

    // 优化 BPF 汇编
    if (bpf_optimize(instrs, &count) < 0) {
        goto error_exit;  // 优化失败
    }

    // 创建 bpf 程序对象
    struct pbf_program *program = malloc(sizeof(struct pbf_program));
    if (!program) {
        bpf_set_errno(BPF_ERROR_OUT_OF_MEMORY);
        goto error_exit;  // 内存分配失败
    }

    program->instrs       = (const uint32_t *)instrs;
    program->instrs_count = count;
    program->pc           = 0;
    program->lcr          = 0;
    memset(program->regs, 0, sizeof(program->regs));
    return program;

error_exit:
    if (instrs) {
        free(instrs);  // 释放指令数组
    }

    if (context) {
        bpf_ast_context_free(context);
    }

    if (ast) {
        bpf_ast_node_free(ast);
    }

    return NULL;
}

int bpf_disassemble(const struct pbf_program *program,
                    void (*callback)(void *, const char *, size_t, uint16_t),
                    void *arg) {
    if (!program || !program->instrs || program->instrs_count == 0) {
        bpf_set_errno(BPF_ERROR_INVALID_ARGUMENT);
        return -1;  // 无效的编译上下文或没有指令可
    }

    for (uint16_t pc = 0; pc < program->instrs_count; pc++) {
        char   buf[64];
        size_t len = bpf_instrin_disassemble(buf, sizeof buf, program->instrs[pc]);
        if (len == 0) {
            bpf_set_errno(BPF_ERROR_INVALID_INSTRUCTION);
            return -1;  // 指令反汇编失败
        }

        // 调用回调函数处理反汇编结果
        callback(arg, buf, len, pc);
    }

    return 0;
}

int bpf_program_execute(struct pbf_program *program, size_t argc, uint64_t argv[]) {
    if (!program || (argc > 0 && !argv) || argc > 4) {
        return BPF_RESULT_INVALID_ARGUMENT;
    }

    uint64_t       *regs   = program->regs;
    const uint32_t *instrs = program->instrs;
    uint16_t        count  = program->instrs_count;
    int64_t         lcr    = 0;

    // 将参数设置到寄存器中
    memcpy(program->regs + 1, argv, argc * sizeof(uint64_t));

    // 执行程序
    for (program->pc = 0; program->pc < program->instrs_count; ++program->pc) {
        unsigned instr  = instrs[program->pc];
        unsigned opcode = instr & BPF_INSTRIN_OPCODE_MASK;

        switch (opcode) {
        case BPF_INSTRIN_LOAD:
            bpf_instrin_execute_load(program, &instrs[program->pc]);
            break;
        case BPF_INSTRIN_SET:
            bpf_instrin_execute_set(program, &instrs[program->pc]);
            break;
        case BPF_INSTRIN_CMP:
            bpf_instrin_execute_cmp(program, &instrs[program->pc]);
            break;
        case BPF_INSTRIN_JMP:
            bpf_instrin_execute_jmp(program, &instrs[program->pc]);
            break;
        case BPF_INSTRIN_JE:
            bpf_instrin_execute_je(program, &instrs[program->pc]);
            break;
        case BPF_INSTRIN_JNE:
            bpf_instrin_execute_jne(program, &instrs[program->pc]);
            break;
        case BPF_INSTRIN_JG:
            bpf_instrin_execute_jg(program, &instrs[program->pc]);
            break;
        case BPF_INSTRIN_JL:
            bpf_instrin_execute_jl(program, &instrs[program->pc]);
            break;
        case BPF_INSTRIN_JNG:
            bpf_instrin_execute_jng(program, &instrs[program->pc]);
            break;
        case BPF_INSTRIN_JNL:
            bpf_instrin_execute_jnl(program, &instrs[program->pc]);
            break;
        case BPF_INSTRIN_RET:
            bpf_instrin_execute_ret(program, &instrs[program->pc]);
            return BPF_RESULT_OK;
        default:
            break;
        }
    }

    return BPF_RESULT_OK;
}

unsigned long bpf_program_result(struct pbf_program *program) { return program->regs[0]; }

void bpf_program_free(struct pbf_program *program) {
    if (!program) {
        return;
    }

    free(program);
}

void bpf_set_errno(int err) {
    s_bpf_errno = err;
}

int bpf_errno() {
    return s_bpf_errno;
}

const char *bpf_strerror(int err) {
    if (err < 0 || err >= sizeof(s_bpf_errno_str) / sizeof(s_bpf_errno_str[0])) {
        return "Unknown error";
    }

    return s_bpf_errno_str[err];
}
