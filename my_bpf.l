%{
#include <stdio.h>
#include <string.h>

#define YYSTYPE char *

#include "my_bpf.tab.h"

%}

%%

"sport" { yylval = strdup(yytext); return SRC_PORT; }
"=="    { return EQUAL; }
[0-9]+  { yylval = strdup(yytext); return NUMBER; }
[ \t]   { };
[\n]    { return 0; }

%%

int yywrap()
{
	return 1;
}
