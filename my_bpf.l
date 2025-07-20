%{
#include <stdio.h>
#include <string.h>

#define YYSTYPE char *

#include "my_bpf.tab.h"

%}

%option noyywrap

%%

"("     { return '('; }
")"     { return ')'; }
"sip"   { yylval = strdup(yytext); return FIELD; }
"dip"   { yylval = strdup(yytext); return FIELD; }
"sport" { yylval = strdup(yytext); return FIELD; }
"dport" { yylval = strdup(yytext); return FIELD; }
"=="    { yylval = strdup(yytext); return COMPARISON; }
"!="    { yylval = strdup(yytext); return COMPARISON; }
"<"     { yylval = strdup(yytext); return COMPARISON; }
"<="    { yylval = strdup(yytext); return COMPARISON; }
">"     { yylval = strdup(yytext); return COMPARISON; }
">="    { yylval = strdup(yytext); return COMPARISON; }
"&&"    { yylval = strdup(yytext); return LOGICAL; }
"||"    { yylval = strdup(yytext); return LOGICAL; }
[0-9]+  { yylval = strdup(yytext); return NUMBER; }
[ \t]   { }
[\n]    { return 0; }

%%
