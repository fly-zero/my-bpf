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

%type <node> filter expr field constant

%%

filter: expr { parse_result = $1; $$ = $1; }
      | expr LOGICAL expr { struct bpf_syntax_node *node = bpf_syntax_node_new(BPF_SYNTAX_NODE_OPERATOR_LOGICAL, $2, yyleng);
                            node->left = $1;
                            node->right = $3;
                            $1->parent = node;
                            $3->parent = node;
                            $$ = node;
                            parse_result = node; }
      ;

expr: field COMPARISON constant { struct bpf_syntax_node *node = bpf_syntax_node_new(BPF_SYNTAX_NODE_OPERATOR_COMPARISON, $2, yyleng);
                                  node->left = $1;
                                  node->right = $3;
                                  $1->parent = node;
                                  $3->parent = node;
                                  $$ = node; }
    ;

field: FIELD { struct bpf_syntax_node *node = bpf_syntax_node_new(BPF_SYNTAX_NODE_FIELD, $1, yyleng);
               $$ = node;}
     ;

constant: NUMBER { struct bpf_syntax_node *node = bpf_syntax_node_new(BPF_SYNTAX_NODE_CONSTANT, $1, yyleng);
                  $$ = node; }
        ;

%%


struct bpf_syntax_node *parse_result = NULL;

static void print_syntax_tree(struct bpf_syntax_node *node, int depth)
{
    if (!node) return;
}

int main()
{
    printf("BPF Filter Parser\n");
    printf("Enter filter expression (e.g., src_port == 80):\n");
    
    if (yyparse() == 0) {
        printf("\nParsing successful!\n");
        if (parse_result) {
            printf("Syntax tree:\n");
            print_syntax_tree(parse_result, 0);
        }
    } else {
        printf("Parsing failed!\n");
    }
    
    return 0;
}

static void yyerror(const char *s)
{
    fprintf(stderr, "Error: %s\n", s);
}
