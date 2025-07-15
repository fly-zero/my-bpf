#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

struct pbf_program;

enum bpf_result {
    BPF_RESULT_OK = 0,
    BPF_RESULT_INVALID_ARGUMENT,
    BPF_RESULT_OUT_OF_MEMORY,
};

/**
 * @brief 创建一个 bpf 程序
 * @return bpf 程序对象
 */
struct pbf_program *bpf_program_new(const void *instrs, size_t count);

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

#ifdef __cplusplus
}
#endif
