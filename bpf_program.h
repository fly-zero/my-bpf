#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define BPF_ERROR_OK                  0  ///< 成功
#define BPF_ERROR_INVALID_ARGUMENT    1  ///< 无效参数
#define BPF_ERROR_OUT_OF_MEMORY       2  ///< 内存不足
#define BPF_ERROR_SYNTAX              3  ///< 语法错误
#define BPF_ERROR_INVALID_INSTRUCTION 4  ///< 无效指令

struct pbf_program;

enum bpf_result {
    BPF_RESULT_OK = 0,
    BPF_RESULT_INVALID_ARGUMENT,
    BPF_RESULT_OUT_OF_MEMORY,
};

/**
 * @brief 注册字段
 *
 * @param name 字段名称
 * @param argn 字段从第几个参数传入
 * @param size 字段大小，单位为字节，1、2、4 或 8
 * @param offset 字段在参数中的偏移量
 * @return int 0 成功，-1 失败
 */
int bpf_register_field(const char *name, uint8_t argn, uint8_t size, uint16_t offset);

/**
 * @brief 根据表达式生成 BPF 汇编代码
 *
 * @param expr 以 0 结尾的表达式字符串
 * @return bpf 程序对象
 */
struct pbf_program *bpf_assemble(const char *expr);

/**
 * @brief 反汇编 BPF 程序
 *
 * @param program bpf 程序
 * @param callback 回调函数，用于处理每条指令的反汇编结果
 * @param arg 回调函数的参数
 * @return int 0 成功，-1 失败
 */
int bpf_disassemble(const struct pbf_program * program,
                    void (*callback)(void *, const char *, size_t, uint16_t),
                    void *arg);

/**
 * @brief 执行 bpf 程序
 * @param program bpf 程序
 * @param argc 参数个数
 * @param argv 参数列表
 * @return 0 表示执行成功，否则表示执行失败
 */
int bpf_program_execute(struct pbf_program *program, size_t argc, uint64_t argv[]);

/**
 * @brief 获取 bpf 程序执行结果
 */
unsigned long bpf_program_result(struct pbf_program *program) __attribute__((nonnull(1)));

/**
 * @brief 释放 bpf 程序
 * @param program bpf 程序
 */
void bpf_program_free(struct pbf_program *program);

/**
 * @brief 设置 bpf 错误码
 *
 * @param err 错误码
 */
void bpf_set_errno(int err);

/**
 * @brief 获取 bpf 错误码
 *
 * @return 错误码
 */
int bpf_errno();

/**
 * @brief 获取 bpf 错误信息
 *
 * @return 错误信息字符串
 */
const char *bpf_strerror(int err);

#ifdef __cplusplus
}
#endif
