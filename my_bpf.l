%{
#include <stdio.h>
#include <string.h>

#define YYSTYPE char *

#include "my_bpf.tab.h"

%}

%%

"sip"   { yylval = yytext; return FIELD; }
"dip"   { yylval = yytext; return FIELD; }
"sport" { yylval = yytext; return FIELD; }
"dport" { yylval = yytext; return FIELD; }
"=="    { yylval = yytext; return COMPARISON; }
"!="    { yylval = yytext; return COMPARISON; }
"&&"    { yylval = yytext; return LOGICAL; }
"||"    { yylval = yytext; return LOGICAL; }
[0-9]+  { yylval = yytext; return NUMBER; }
[ \t]   { }
[\n]    { return 0; }

%%

int yywrap()
{
	return 1;
}
