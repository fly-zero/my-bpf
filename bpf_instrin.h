#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BPF_STATIC_ASSERT(COND, MSG) typedef char static_assertion_##MSG[(COND) ? 1 : -1]

enum bpf_instrin_type
{
    BPF_INSTRIN_LOAD,  ///< 从内存中加载数据到寄存器
    BPF_INSTRIN_SET,   ///< 设置立即数到寄存器
    BPF_INSTRIN_CMP,   ///< 比较两个寄存器的值
    BPF_INSTRIN_JE,    ///< 相等跳转
    BPF_INSTRIN_JNE,   ///< 不相等跳转
    BPF_INSTRIN_JG,    ///< 大于跳转
    BPF_INSTRIN_JL,    ///< 小于跳转
    BPF_INSTRIN_JNG,   ///< 小于等于跳转
    BPF_INSTRIN_JNL,   ///< 大于等于跳转
};

/**
 * @brief 从内存中加载数据到寄存器
 *
 * @note 从内存 [src + offset] 处加载 (1 << width) 字节数据到寄存器 dst 中
 */
struct bpf_instrin_load
{
    uint32_t opcode :  6;  ///< 操作码 BPF_INSTRIN_LOAD
    uint32_t width  :  2;  ///< 数据宽度，1 << width 字节
    uint32_t dst    :  4;  ///< 目标寄存器
    uint32_t src    :  4;  ///< 保存内存地址的寄存器
    uint32_t offset : 16;  ///< 内存地址偏移
};

BPF_STATIC_ASSERT(sizeof(struct bpf_instrin_load) == sizeof(uint32_t),
                  instrin_struct_size_must_be_4_bytes);

/**
 * @brief 设置立即数到寄存器
 *
 * @note 将指令中的立即数 value 设置到寄存器 dst 的 [offset * 16, offset * 16 + 16) 位上
 */
struct bpf_instrin_set
{
    uint32_t opcode :  6;  ///< 操作码 BPF_INSTRIN_SET
    uint32_t offset :  2;  ///< width of data
    uint32_t dst    :  4;  ///< destination register
    uint32_t        :  4;  ///< reserved
    uint32_t value  : 16;  ///< source value
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
struct bpf_instrin_cmp
{
    uint32_t opcode :  6;  ///< 操作码 BPF_INSTRIN_CMP
    uint32_t        :  2;  ///< 保留位
    uint32_t lr     :  4;  ///< 左操作数寄存器
    uint32_t rr     :  4;  ///< 右操作数寄存器
    uint32_t        : 16;  ///< reserved
};

BPF_STATIC_ASSERT(sizeof(struct bpf_instrin_cmp) == sizeof(uint32_t),
                  instrin_struct_size_must_be_4_bytes);

/**
 * @brief 跳转
 *
 * @note 根据跳转条件和 lcr 的值跳转 offset 个指令
 */
struct bpf_instrin_condition_jump
{
    uint32_t opcode :  6;  ///< 操作码，BPF_INSTRIN_J*
    uint32_t        : 10;  ///< 保留位
    uint32_t offset : 16;  ///< 跳转偏移量，可以为负数
};

BPF_STATIC_ASSERT(sizeof(struct bpf_instrin_condition_jump) == sizeof(uint32_t),
                  instrin_struct_size_must_be_4_bytes);

#ifdef __cplusplus
}
#endif