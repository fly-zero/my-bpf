%{
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bpf_ast.h"
#include "bpf_program.h"

extern int yylex();

extern void yy_scan_string(const char *str);

extern int yylex_destroy();  // 添加词法分析器清理函数声明

static void yyerror(const char *);

static const char *get_swapped_comparison(const char *op);

static struct bpf_ast_node *s_ast_root;

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
    s_ast_root = $1; 
    $$ = $1;
};

expr
: factor LOGICAL factor {
    struct bpf_ast_node *node;
    if (strcmp($2, "&&") == 0) {
        node = bpf_ast_node_new(BPF_AST_NODE_IF, $2);
    } else if (strcmp($2, "||") == 0) {
        node = bpf_ast_node_new(BPF_AST_NODE_IF_FALSE, $2);
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
    struct bpf_ast_node *node = bpf_ast_node_new(BPF_AST_NODE_COMPARISON, $2);
    node->left = $1;
    node->right = $3;
    $1->parent = node;
    $3->parent = node;
    $$ = node;
}
| constant COMPARISON field {
    const char *swapped_op = get_swapped_comparison($2);
    struct bpf_ast_node *node = bpf_ast_node_new(BPF_AST_NODE_COMPARISON, strdup(swapped_op));
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
    struct bpf_ast_node *node = bpf_ast_node_new(BPF_AST_NODE_FIELD, $1);
    $$ = node;
};

constant
: NUMBER {
    struct bpf_ast_node *node = bpf_ast_node_new(BPF_AST_NODE_CONSTANT, $1);
    $$ = node;
};

%%

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

struct bpf_ast_node *bpf_compile(const char *expr) {
    assert(expr);

    // 使用命令行参数作为输入
    yy_scan_string(expr);

    // 解析输入
    if (yyparse() != 0) {
        bpf_set_errno(BPF_ERROR_SYNTAX);
        goto error_exit;
    }

    // 清理词法分析器分配的缓冲区
    yylex_destroy();

    if (!s_ast_root) {
        bpf_set_errno(BPF_ERROR_SYNTAX);
    }

    return s_ast_root;

error_exit:
    // 释放语法树
    if (s_ast_root) {
        bpf_ast_node_free(s_ast_root);
        s_ast_root = NULL;
    }

    return NULL;
}
