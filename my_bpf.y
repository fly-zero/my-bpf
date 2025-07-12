%{
#include <stdio.h>
#include <stdlib.h>

#include "syntax.h"

extern int yylex();

static void yyerror(const char *);

static void print_syntax_tree(struct bpf_syntax_node *node, int depth);

extern struct bpf_syntax_node *parse_result;

extern int yyleng;
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
    struct bpf_syntax_node *label_node = bpf_syntax_node_new(BPF_SYNTAX_NODE_JUMP_LABEL, NULL);

    // 创建条件跳转结点，用于实现逻辑运算的短路求值
    struct bpf_syntax_node *jump_node  = bpf_syntax_node_new(BPF_SYNTAX_NODE_JUMP_IF, $2);
    jump_node->left = $1;
    jump_node->right = label_node;
    $1->parent = jump_node;
    label_node->parent = jump_node;

    // 创建一个取右子表达式的结点
    struct bpf_syntax_node *right_expr = bpf_syntax_node_new(BPF_SYNTAX_NODE_RIGHT_SUB_EXPRESSION, NULL);
    right_expr->left = jump_node;
    right_expr->right = $3;
    jump_node->parent = right_expr;
    $3->parent = right_expr;

    $$ = right_expr;
};

factor
: field COMPARISON constant {
    struct bpf_syntax_node *node = bpf_syntax_node_new(BPF_SYNTAX_NODE_OPERATOR_COMPARISON, $2);
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
    struct bpf_syntax_node *node = bpf_syntax_node_new(BPF_SYNTAX_NODE_FIELD, $1);
    $$ = node;
};

constant
: NUMBER {
    struct bpf_syntax_node *node = bpf_syntax_node_new(BPF_SYNTAX_NODE_CONSTANT, $1);
    $$ = node;
};

%%

struct bpf_syntax_node *parse_result = NULL;

static void print_syntax_tree(struct bpf_syntax_node *node, int depth) {
    if (!node) return;

    bpf_syntax_asm(node); // 生成 BPF 汇编
}

static void register_global_field() {
    // 注册全局字段
    bpf_syntax_register_field("sport", 0, 2, 0);
    bpf_syntax_register_field("dport", 0, 2, 2);
}

int main()
{
    register_global_field(); // 注册全局字段

    if (yyparse() == 0) {
        printf("\nParsing successful!\n");
        if (parse_result) {
            printf("ASM:\n");
            print_syntax_tree(parse_result, 0);
        }
    } else {
        printf("Parsing failed!\n");
    }
    
    return 0;
}

static void yyerror(const char *s) {
    fprintf(stderr, "Error: %s\n", s);
}
