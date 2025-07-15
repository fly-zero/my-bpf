#include "bpf_instrin.h"

#include <stdio.h>

/**
 * @brief 寄存器编号到名称的映射
 */
static const char *s_bpf_register_names[] = {
    "cr",
    "r0",
    "r1",
    "r2",
    "r3",
    "r4",
    "r5",
    "r6",
    "r7",
    "r8",
    "r9",
    "r10",
    "r11",
    "r12",
    "r13",
    "r14",
    "r15",
};

static const char *bpf_register_name(int reg) {
    // 检查寄存器编号是否在有效范围内
    if (reg < BPF_REGISTER_LCR || reg > BPF_REGISTER_R15) {
        return "no_reg";  // 返回无效寄存器名称
    }

    return s_bpf_register_names[reg];  // 返回寄存器名称
}

static inline size_t bpf_instrin_disassemble_load(char *buff, size_t size, uint32_t instr) {
    const struct bpf_instrin_load *load = (const struct bpf_instrin_load *)&instr;
    return snprintf(buff,
                    size,
                    "%-4s [r%d:%d:%d], r%d",
                    "load",
                    load->src,
                    load->offset,
                    1 << load->width,
                    load->dst);
}

static inline size_t bpf_instrin_disassemble_set(char *buff, size_t size, uint32_t instr) {
    const struct bpf_instrin_set *set = (const struct bpf_instrin_set *)&instr;
    return snprintf(buff, size, "%-4s %d << %d, r%d", "set", set->value, set->offset, set->dst);
}

static inline size_t bpf_instrin_disassemble_cmp(char *buff, size_t size, uint32_t instr) {
    const struct bpf_instrin_cmp *cmp = (const struct bpf_instrin_cmp *)&instr;
    return snprintf(buff, size, "%-4s r%d, r%d", "cmp", cmp->lr, cmp->rr);
}

static inline size_t bpf_instrin_disassemble_jmp(char *buff, size_t size, uint32_t instr) {
    const struct bpf_instrin_jmp *jmp = (const struct bpf_instrin_jmp *)&instr;
    return snprintf(buff, size, "%-4s %d", "jmp", jmp->offset);
}

static inline size_t bpf_instrin_disassemble_je(char *buff, size_t size, uint32_t instr) {
    const struct bpf_instrin_jmp *je = (const struct bpf_instrin_jmp *)&instr;
    return snprintf(buff, size, "%-4s %d", "je", je->offset);
}

static inline size_t bpf_instrin_disassemble_jne(char *buff, size_t size, uint32_t instr) {
    const struct bpf_instrin_jmp *jne = (const struct bpf_instrin_jmp *)&instr;
    return snprintf(buff, size, "%-4s %d", "jne", jne->offset);
}

static inline size_t bpf_instrin_disassemble_jg(char *buff, size_t size, uint32_t instr) {
    const struct bpf_instrin_jmp *jg = (const struct bpf_instrin_jmp *)&instr;
    return snprintf(buff, size, "%-4s %d", "jg", jg->offset);
}

static inline size_t bpf_instrin_disassemble_jl(char *buff, size_t size, uint32_t instr) {
    const struct bpf_instrin_jmp *jl = (const struct bpf_instrin_jmp *)&instr;
    return snprintf(buff, size, "%-4s %d", "jl", jl->offset);
}

static inline size_t bpf_instrin_disassemble_jng(char *buff, size_t size, uint32_t instr) {
    const struct bpf_instrin_jmp *jng = (const struct bpf_instrin_jmp *)&instr;
    return snprintf(buff, size, "%-4s %d", "jng", jng->offset);
}

static inline size_t bpf_instrin_disassemble_jnl(char *buff, size_t size, uint32_t instr) {
    const struct bpf_instrin_jmp *jnl = (const struct bpf_instrin_jmp *)&instr;
    return snprintf(buff, size, "%-4s %d", "jnl", jnl->offset);
}

static inline size_t bpf_instrin_disassemble_ret(char *buff, size_t size, uint32_t instr) {
    (void)instr;  // 避免未使用参数的警告
    return snprintf(buff, size, "%-4s", "ret");
}

size_t bpf_instrin_disassemble(char *buff, size_t size, uint32_t instr) {
    uint32_t opcode = instr & BPF_INSTRIN_OPCODE_MASK;
    switch (opcode) {
    case BPF_INSTRIN_LOAD:
        return bpf_instrin_disassemble_load(buff, size, instr);
    case BPF_INSTRIN_SET:
        return bpf_instrin_disassemble_set(buff, size, instr);
    case BPF_INSTRIN_CMP:
        return bpf_instrin_disassemble_cmp(buff, size, instr);
    case BPF_INSTRIN_JMP:
        return bpf_instrin_disassemble_jmp(buff, size, instr);
    case BPF_INSTRIN_JE:
        return bpf_instrin_disassemble_je(buff, size, instr);
    case BPF_INSTRIN_JNE:
        return bpf_instrin_disassemble_jne(buff, size, instr);
    case BPF_INSTRIN_JG:
        return bpf_instrin_disassemble_jg(buff, size, instr);
    case BPF_INSTRIN_JL:
        return bpf_instrin_disassemble_jl(buff, size, instr);
    case BPF_INSTRIN_JNG:
        return bpf_instrin_disassemble_jng(buff, size, instr);
    case BPF_INSTRIN_JNL:
        return bpf_instrin_disassemble_jnl(buff, size, instr);
    case BPF_INSTRIN_RET:
        return bpf_instrin_disassemble_ret(buff, size, instr);
    default:
        return 0;
    }
}
