#include <stdio.h>

#include "bpf_program.h"

static void bpf_disassemble_callback(void *arg, const char *instr, size_t len, uint16_t pc) {
    // 打印反汇编指令
    printf("%04x: %.*s\n", pc, (int)len, instr);
}

/**
 * @brief 计算字段的大小
 *
 * @param t 结构体类型
 * @param m 字段名称
 * @return 字段大小
 */
#define sizeof_filed(t, m) sizeof(((t *)0)->m)

/**
 * @brief 注册全局字段
 *
 * @param n 字段从第几个参数传入
 * @param t 结构体类型
 * @param m 字段名称
 */
#define register_bpf_filed(n, t, m) bpf_register_field(#m, n, sizeof_filed(t, m), offsetof(t, m))

struct packet_info {
    unsigned short sport;
    unsigned short dport;
};

static void register_global_field() {
    // 注册全局字段
    register_bpf_filed(0, struct packet_info, sport);
    register_bpf_filed(0, struct packet_info, dport);
}

int main(int argc, char **argv) {
    // 检查命令行参数
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filter_expression>\n", argv[0]);
        return 1;
    }

    // 注册全局字段
    register_global_field();

    // 生成 BPF 程序
    struct pbf_program *program = bpf_assemble(argv[1]);
    if (!program) {
        fprintf(stderr, "Failed to assemble BPF program: %s\n", bpf_strerror(bpf_errno()));
        return 1;
    }

    // 反汇编 BPF 程序
    if (bpf_disassemble(program, bpf_disassemble_callback, NULL) != 0) {
        fprintf(stderr, "Failed to disassemble BPF program: %s\n", bpf_strerror(bpf_errno()));
        bpf_program_free(program);
        return 1;
    }
}