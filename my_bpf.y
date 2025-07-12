%{
#include <stdio.h>
#include <stdlib.h>

#include "syntax.h"

extern int yylex();

extern int yylex_destroy();  // 添加词法分析器清理函数声明

static void yyerror(const char *);

static void print_syntax_tree(struct bpf_syntax_node *node, int depth);

extern struct bpf_syntax_node *parse_result;

static struct bpf_compilation_context *context = NULL;

%}

%union {
    char *str;                        /* 字符串值，用于词法单元 */
    struct bpf_syntax_node *node;     /* 语法树节点 */
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
    // 创建一个跳转标签结点
    struct bpf_syntax_node *label_node = bpf_syntax_node_new(context, BPF_SYNTAX_NODE_LABEL, NULL);

    // 创建条件跳转结点，用于实现逻辑运算的短路求值
    struct bpf_syntax_node *jump_node  = bpf_syntax_node_new(context, BPF_SYNTAX_NODE_JUMP_IF, $2);
    jump_node->left = $1;
    jump_node->right = label_node;
    $1->parent = jump_node;
    label_node->parent = jump_node;

    // 创建一个取右子表达式的结点
    struct bpf_syntax_node *right_expr = bpf_syntax_node_new(context, BPF_SYNTAX_NODE_RIGHT_SUB_EXPR, NULL);
    right_expr->left = jump_node;
    right_expr->right = $3;
    jump_node->parent = right_expr;
    $3->parent = right_expr;

    $$ = right_expr;
}
| factor {
    $$ = $1;
};

factor
: field COMPARISON constant {
    struct bpf_syntax_node *node = bpf_syntax_node_new(context, BPF_SYNTAX_NODE_COMPARISON, $2);
    node->left = $1;
    node->right = $3;
    $1->parent = node;
    $3->parent = node;
    $$ = node;
    }
| '(' expr ')' {
    $$ = $2;
};

field
: FIELD {
    struct bpf_syntax_node *node = bpf_syntax_node_new(context, BPF_SYNTAX_NODE_FIELD, $1);
    $$ = node;
};

constant
: NUMBER {
    struct bpf_syntax_node *node = bpf_syntax_node_new(context, BPF_SYNTAX_NODE_CONSTANT, $1);
    $$ = node;
};

%%

struct bpf_syntax_node *parse_result = NULL;

static void print_syntax_tree(struct bpf_syntax_node *node, int depth) {
    if (!node) {
        return;
    }

    bpf_asm(context, node); // 生成 BPF 汇编
}

static void register_global_field() {
    // 注册全局字段
    bpf_syntax_register_field("sport", 0, 2, 0);
    bpf_syntax_register_field("dport", 0, 2, 2);
}

int main() {
    // 注册全局字段
    register_global_field();

    // 创建编译上下文
    context = bpf_compilation_context_new();
    if (!context) {
        fprintf(stderr, "Failed to create compilation context.\n");
        return 1;
    }

    // 解析输入
    if (yyparse() == 0) {
        printf("\nParsing successful!\n");
        if (parse_result) {
            printf("ASM:\n");
            print_syntax_tree(parse_result, 0);
        }
    } else {
        printf("Parsing failed!\n");
    }

    // 释放语法树
    if (parse_result) {
        bpf_syntax_node_free(context, parse_result);
        parse_result = NULL;
    }

    // 释放编译上下文
    bpf_compilation_context_free(context);
    context = NULL;

    // 清理词法分析器分配的缓冲区
    yylex_destroy();

    return 0;
}

static void yyerror(const char *s) {
    fprintf(stderr, "Error: %s\n", s);
}
