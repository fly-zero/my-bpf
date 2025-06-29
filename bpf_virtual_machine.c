#include "bpf_virtual_machine.h"
#include "bpf_instrin.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

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
struct pbf_program
{
    const uint32_t *instrs;        ///< 程序指令开始地址
    uint16_t        instrs_count;  ///< 指令数量
    uint16_t        pc;            ///< 程序计数器
    int64_t         lcr;           ///< 上一次比较的结果
    uint64_t        regs[16];      ///< 寄存器
};

static inline void bpf_instrin_load(struct pbf_program *program, const uint32_t *instr)
{
    uint64_t                      *regs = program->regs;
    const struct bpf_instrin_load *load = (const struct bpf_instrin_load *)instr;
    memcpy(&regs[load->dst], (uint8_t *)regs[load->src] + load->offset, 1 << load->width);
}

static inline void bpf_instrin_set(struct pbf_program *program, const uint32_t *instr)
{
    uint64_t                     *regs = program->regs;
    const struct bpf_instrin_set *set  = (const struct bpf_instrin_set *)instr;
    regs[set->dst]                     = regs[set->dst] | (set->value << set->offset);
}

static inline void bpf_instrin_cmp(struct pbf_program *program, const uint32_t *instr)
{
    uint64_t                     *regs = program->regs;
    const struct bpf_instrin_cmp *cmp  = (const struct bpf_instrin_cmp *)instr;
    program->lcr                       = regs[cmp->lr] - regs[cmp->rr];
}

static inline void bpf_instrin_je(struct pbf_program *program, const uint32_t *instr)
{
    const struct bpf_instrin_condition_jump *cj = (const struct bpf_instrin_condition_jump *)instr;
    if (program->lcr == 0) {
        program->pc += cj->offset;
    }
}

static inline void bpf_instrin_jne(struct pbf_program *program, const uint32_t *instr)
{
    const struct bpf_instrin_condition_jump *cj = (const struct bpf_instrin_condition_jump *)instr;
    if (program->lcr != 0) {
        program->pc += cj->offset;
    }
}

static inline void bpf_instrin_jg(struct pbf_program *program, const uint32_t *instr)
{
    const struct bpf_instrin_condition_jump *cj = (const struct bpf_instrin_condition_jump *)&instr;
    if (program->lcr > 0) {
        program->pc += cj->offset;
    }
}

static inline void bpf_instrin_jl(struct pbf_program *program, const uint32_t *instr)
{
    const struct bpf_instrin_condition_jump *cj = (const struct bpf_instrin_condition_jump *)&instr;
    if (program->lcr < 0) {
        program->pc += cj->offset;
    }
}

static inline void bpf_instrin_jng(struct pbf_program *program, const uint32_t *instr)
{
    const struct bpf_instrin_condition_jump *cj = (const struct bpf_instrin_condition_jump *)&instr;
    if (program->lcr <= 0) {
        program->pc += cj->offset;
    }
}

static inline void bpf_instrin_jnl(struct pbf_program *program, const uint32_t *instr)
{
    const struct bpf_instrin_condition_jump *cj = (const struct bpf_instrin_condition_jump *)&instr;
    if (program->lcr >= 0) {
        program->pc += cj->offset;
    }
}

struct pbf_program *bpf_new(const void *instrs, size_t count)
{
    if (!instrs || count == 0) {
        return NULL;
    }

    if (count > UINT16_MAX) {
        return NULL;
    }

    struct pbf_program *program = malloc(sizeof(struct pbf_program));
    if (!program) {
        return NULL;
    }

    program->instrs       = (const uint32_t *)instrs;
    program->instrs_count = count;
    program->pc           = 0;
    program->lcr          = 0;
    memset(program->regs, 0, sizeof(program->regs));
    return program;
}

int bpf_execute(struct pbf_program *program, size_t argc, uint64_t argv[])
{
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
        unsigned instr = instrs[program->pc];
        unsigned opcode = instr >> 26;

        switch (opcode) {
        case BPF_INSTRIN_LOAD:
            bpf_instrin_load(program, &instrs[program->pc]);
            break;

        case BPF_INSTRIN_SET:
            bpf_instrin_set(program, &instrs[program->pc]);
            break;

        case BPF_INSTRIN_CMP:
            bpf_instrin_cmp(program, &instrs[program->pc]);
            break;

        case BPF_INSTRIN_JE:
            bpf_instrin_je(program, &instrs[program->pc]);
            break;

        case BPF_INSTRIN_JNE:
            bpf_instrin_jne(program, &instrs[program->pc]);
            break;

        case BPF_INSTRIN_JG:
            bpf_instrin_jg(program, &instrs[program->pc]);
            break;

        case BPF_INSTRIN_JL:
            bpf_instrin_jl(program, &instrs[program->pc]);
            break;

        case BPF_INSTRIN_JNG:
            bpf_instrin_jng(program, &instrs[program->pc]);
            break;

        case BPF_INSTRIN_JNL:
            bpf_instrin_jnl(program, &instrs[program->pc]);
            break;

        default:
            break;
        }
    }

    return BPF_RESULT_OK;
}

unsigned long bpf_result(struct pbf_program *program)
{
    return program->regs[0];
}

void bpf_free(struct pbf_program *program)
{
    if (!program) {
        return;
    }

    free(program);
}
