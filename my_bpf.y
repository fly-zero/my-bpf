%{
#include <stdio.h>
#include <stdlib.h>

#define YYSTYPE char *

extern int yylex();

static void yyerror(const char *);
%}

%token SRC_PORT
%token EQUAL
%token NUMBER

%%

filter: expr { printf("%s\n", $1); }
      ;

expr: keyword EQUAL constant { printf("%s == %s\n", $1, $3); $$ = "1"; free($1); free($3); }
	;

keyword: SRC_PORT { $$ = $1; }
       ;

constant: NUMBER { $$ = $1; }
        ;

%%

int main()
{
	yyparse();
}

static void yyerror(const char *s)
{
	fprintf(stderr, "Error: %s\n", s);
}
