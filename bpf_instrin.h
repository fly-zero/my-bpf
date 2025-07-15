#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BPF_STATIC_ASSERT(COND, MSG) typedef char static_assertion_##MSG[(COND) ? 1 : -1]

enum bpf_register_type {
    BPF_REGISTER_LCR,  ///< 上一次比较结果寄器
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

enum bpf_instrin_type {
    BPF_INSTRIN_LOAD,  ///< 从内存中加载数据到寄存器
    BPF_INSTRIN_SET,   ///< 设置立即数到寄存器
    BPF_INSTRIN_CMP,   ///< 比较两个寄存器的值
    BPF_INSTRIN_JMP,   ///< 跳转指令
    BPF_INSTRIN_JE,    ///< 相等跳转
    BPF_INSTRIN_JNE,   ///< 不相等跳转
    BPF_INSTRIN_JG,    ///< 大于跳转
    BPF_INSTRIN_JL,    ///< 小于跳转
    BPF_INSTRIN_JNG,   ///< 小于等于跳转
    BPF_INSTRIN_JNL,   ///< 大于等于跳转
    BPF_INSTRIN_RET,   ///< 返回
};

#define BPF_INSTRIN_OPCODE_MASK 0x3F

/**
 * @brief 寄存器之间的移动指令
 *
 * @note 将寄存器 src 的值移动到寄存器 dst 中
 */
struct bpf_instrin_mov {
    uint32_t opcode : 6;  ///< 操作码 BPF_INSTRIN_MOV
    uint32_t        : 2;  ///< 保留位
    uint32_t dst    : 4;  ///< 目标寄存器
    uint32_t src    : 4;  ///< 源寄存器
    uint32_t        : 16; ///< 保留位
};

BPF_STATIC_ASSERT(sizeof(struct bpf_instrin_mov) == sizeof(uint32_t),
                  instrin_struct_size_must_be_4_bytes);

/**
 * @brief 从内存中加载数据到寄存器
 *
 * @note 从内存 [src + offset] 处加载 (1 << width) 字节数据到寄存器 dst 中
 */
struct bpf_instrin_load {
    uint32_t opcode : 6;   ///< 操作码 BPF_INSTRIN_LOAD
    uint32_t width  : 2;   ///< 数据宽度，1 << width 字节
    uint32_t dst    : 4;   ///< 目标寄存器
    uint32_t src    : 4;   ///< 保存内存地址的寄存器
    uint32_t offset : 16;  ///< 内存地址偏移
};

BPF_STATIC_ASSERT(sizeof(struct bpf_instrin_load) == sizeof(uint32_t),
                  instrin_struct_size_must_be_4_bytes);

/**
 * @brief 设置立即数到寄存器
 *
 * @note 将指令中的立即数 value 设置到寄存器 dst 的 [offset * 16, offset * 16 + 16) 位上
 */
struct bpf_instrin_set {
    uint32_t opcode :  6;  ///< 操作码 BPF_INSTRIN_SET
    uint32_t offset :  2;  ///< 数据偏移量，表示寄存器 dst 的第 offset * 16 位开始设置
    uint32_t dst    :  4;  ///< 目标寄存器
    uint32_t        :  4;  ///< 保留位
    uint32_t value  : 16;  ///< 立即数值，范围为 0 ~ 65535
};

BPF_STATIC_ASSERT(sizeof(struct bpf_instrin_set) == sizeof(uint32_t),
                  instrin_struct_size_must_be_4_bytes);

/**
 * @brief 比较两个寄存器的值
 *
 * @note if lr < rr then lcr = -1
 *       if lr == rr then lcr = 0
 *       if lr > rr then lcr = 1
 */
struct bpf_instrin_cmp {
    uint32_t opcode :  6;  ///< 操作码 BPF_INSTRIN_CMP
    uint32_t        :  2;  ///< 保留位
    uint32_t lr     :  4;  ///< 左操作数寄存器
    uint32_t rr     :  4;  ///< 右操作数寄存器
    uint32_t        : 16;  ///< reserved
};

BPF_STATIC_ASSERT(sizeof(struct bpf_instrin_cmp) == sizeof(uint32_t),
                  instrin_struct_size_must_be_4_bytes);

/**
 * @brief 跳转指令
 */
struct bpf_instrin_jmp {
    uint32_t opcode :  6;  ///< 操作码 BPF_INSTRIN_J*
    uint32_t        : 10;  ///< 保留位
    uint32_t offset : 16;  ///< 跳转偏移量，可以为负数
};

BPF_STATIC_ASSERT(sizeof(struct bpf_instrin_jmp) == sizeof(uint32_t),
                  instrin_struct_size_must_be_4_bytes);

/**
 * @brief 返回
 */
struct bpf_instrin_ret {
    uint32_t opcode :  6;  ///< 操作码 BPF_INSTRIN_RET
    uint32_t        : 26;        ///< 保留位
};

BPF_STATIC_ASSERT(sizeof(struct bpf_instrin_ret) == sizeof(uint32_t),
                  instrin_struct_size_must_be_4_bytes);

/**
 * @brief 创建一个 load 指令
 */
static inline uint32_t bpf_instrin_load(uint32_t width,
                                        uint32_t dst,
                                        uint32_t src,
                                        uint32_t offset) {
    struct bpf_instrin_load instr = {
        .opcode = BPF_INSTRIN_LOAD,
        .width  = width,
        .dst    = dst,
        .src    = src,
        .offset = offset,
    };

    return *(uint32_t *)&instr;
}

/**
 * @brief 创建一个 set 指令
 */
static inline uint32_t bpf_instrin_set(uint32_t offset, uint32_t dst, uint32_t value) {
    struct bpf_instrin_set instr = {
        .opcode = BPF_INSTRIN_SET,
        .offset = offset,
        .dst    = dst,
        .value  = value,
    };

    return *(uint32_t *)&instr;
}

/**
 * @brief 创建一个 cmp 指令
 */
static inline uint32_t bpf_instrin_cmp(uint32_t lr, uint32_t rr) {
    struct bpf_instrin_cmp instr = {
        .opcode = BPF_INSTRIN_CMP,
        .lr     = lr,
        .rr     = rr,
    };

    return *(uint32_t *)&instr;
}

/**
 * @brief 创建一个 jmp 指令
 */
static inline uint32_t bpf_instrin_jmp(uint32_t offset) {
    struct bpf_instrin_jmp instr = {
        .opcode = BPF_INSTRIN_JMP,
        .offset = offset,
    };

    return *(uint32_t *)&instr;
}

/**
 * @brief 创建一个 je 指令
 */
static inline uint32_t bpf_instrin_je(uint32_t offset) {
    struct bpf_instrin_jmp instr = {
        .opcode = BPF_INSTRIN_JE,
        .offset = offset,
    };

    return *(uint32_t *)&instr;
}

/**
 * @brief 创建一个 jne 指令
 */
static inline uint32_t bpf_instrin_jne(uint32_t offset) {
    struct bpf_instrin_jmp instr = {
        .opcode = BPF_INSTRIN_JNE,
        .offset = offset,
    };

    return *(uint32_t *)&instr;
}

/**
 * @brief 创建一个 ret 指令
 */
static inline uint32_t bpf_instrin_ret() {
    struct bpf_instrin_ret instr = {
        .opcode = BPF_INSTRIN_RET,
    };

    return *(uint32_t *)&instr;
}

/**
 * @brief 反汇编一条指令
 *
 * @param buff 输出缓冲区地址
 * @param size 输出缓冲区大小
 * @param instr 指令
 * @return size_t 输出字符串长度
 */
size_t bpf_instrin_disassemble(char *buff, size_t size, uint32_t instr);

#ifdef __cplusplus
}
#endif