%{
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_ast.h"

extern int yylex();

extern void yy_scan_string(const char *str);

extern int yylex_destroy();  // 添加词法分析器清理函数声明

static void yyerror(const char *);

static const char *get_swapped_comparison(const char *op);

static struct bpf_ast_node *parse_result;

static struct bpf_ast_context *context = NULL;

%}

%union {
    char                *str;   /* 字符串值，用于词法单元 */
    struct bpf_ast_node *node;  /* 语法树节点 */
}

%token <str> FIELD COMPARISON LOGICAL NUMBER

%type <node> program expr factor field constant

%%

program
: expr {
    parse_result = $1; 
    $$ = $1;
};

expr
: factor LOGICAL factor {
    struct bpf_ast_node *node;
    if (strcmp($2, "&&") == 0) {
        node = bpf_ast_node_new(context, BPF_AST_NODE_IF, $2);
    } else if (strcmp($2, "||") == 0) {
        node = bpf_ast_node_new(context, BPF_AST_NODE_IF_FALSE, $2);
    } else {
        assert(0);
    }

    node->left = $1;
    node->right = $3;
    $1->parent = node;
    $3->parent = node;
    $$ = node;
}
| factor {
    $$ = $1;
};

factor
: field COMPARISON constant {
    struct bpf_ast_node *node = bpf_ast_node_new(context, BPF_AST_NODE_COMPARISON, $2);
    node->left = $1;
    node->right = $3;
    $1->parent = node;
    $3->parent = node;
    $$ = node;
}
| constant COMPARISON field {
    const char *swapped_op = get_swapped_comparison($2);
    struct bpf_ast_node *node = bpf_ast_node_new(context, BPF_AST_NODE_COMPARISON, strdup(swapped_op));
    node->left = $3;
    node->right = $1;
    $3->parent = node;
    $1->parent = node;
    $$ = node;
    free($2);
}
| '(' expr ')' {
    $$ = $2;
};

field
: FIELD {
    struct bpf_ast_node *node = bpf_ast_node_new(context, BPF_AST_NODE_FIELD, $1);
    $$ = node;
};

constant
: NUMBER {
    struct bpf_ast_node *node = bpf_ast_node_new(context, BPF_AST_NODE_CONSTANT, $1);
    $$ = node;
};

%%

static void register_global_field() {
    // 注册全局字段
    bpf_ast_register_field("sport", 0, 2, 0);
    bpf_ast_register_field("dport", 0, 2, 2);
}

static void disassemble_callback(const char *stmt, size_t length, uint16_t pc, void *arg) {
    (void)arg;
    printf("%04hx: %.*s\n", pc, (int)length, stmt);
}

static void yyerror(const char *s) {
    fprintf(stderr, "Error: %s\n", s);
}

static const char *get_swapped_comparison(const char *op) {
    if (strcmp(op, "==") == 0) {
        return "==";
    } else if (strcmp(op, "!=") == 0) {
        return "!=";
    } else if (strcmp(op, "<") == 0) {
        return ">";
    } else if (strcmp(op, ">") == 0) {
        return "<";
    } else if (strcmp(op, "<=") == 0) {
        return ">=";
    } else if (strcmp(op, ">=") == 0) {
        return "<=";
    }

    return NULL;  // 未知操作符
}

int main(int argc, char **argv) {
    // 检查命令行参数
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <filter_expression>\n", argv[0]);
        return 1;
    }

    // 注册全局字段
    register_global_field();

    // 创建编译上下文
    context = bpf_ast_context_new();
    if (!context) {
        fprintf(stderr, "Failed to create ast context.\n");
        return 1;
    }

    // 使用命令行参数作为输入
    yy_scan_string(argv[1]);

    // 解析输入
    if (yyparse() == 0 && parse_result) {
        printf("Compiling BPF program...\n");
        bpf_assemble(context, parse_result);
        bpf_disassemble(context, disassemble_callback, NULL);
        printf("\noptimizing BPF program...\n");
        bpf_optimize(context);
        bpf_disassemble(context, disassemble_callback, NULL);
    } else {
        fprintf(stderr, "Parsing failed!\n");
    }

    // 释放语法树
    if (parse_result) {
        bpf_ast_node_free(context, parse_result);
        parse_result = NULL;
    }

    // 释放编译上下文
    bpf_ast_context_free(context);
    context = NULL;

    // 清理词法分析器分配的缓冲区
    yylex_destroy();

    return 0;
}
