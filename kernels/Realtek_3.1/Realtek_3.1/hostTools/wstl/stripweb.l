%{
	/*
	version 1.5
	Thu Mar 15 11:11:08 CDT 2007 {js} is an html keyword, thus is case insensitive
	Fri Mar 16 12:28:48 CDT 2007 kill blank lines on single pass
	Fri Mar 16 16:50:49 CDT 2007 kw can get joined to non-keyword if source has no space, fixed
	Tue Mar 27 16:46:02 CDT 2007 add debug/usage, find puncuation
	Mon Apr  2 10:50:26 CDT 2007 old school C comments used lex rule, not flex rule, also embedded single/double quotes
	*/
	int inJS = 0;
	int text = 0;
	int debug = 0;
/* these are the javascript keywords:

	as break case class const continue default delete do else export extends false finally for function if import in instanceof is
	namespace new null package private public return super switch this throw true try typeof use var void while with

   but we can leave out the ones that must be followed by a non-identifer
*/


%}
kw	as|break|case|class|const|continue|delete|do|else|export|extends|function|get|import|in|include|instanceof|is|namespace|new|package|private|public|return|set|super|throw|typeof|use|var|void


ws	[ \t]
js	[Ss][Cc][Rr][Ii][Pp][Tt]
tag	[_a-zA-Z][_a-zA-Z0-9]*
punc	[^ \t\n_a-zA-Z0-9\"\'\/\<]

%%
[<]{js}[^>]*[>]	{ inJS = 1; ECHO; text++; }
[<][/]{js}[^>]*[>]	{ inJS = 0; ECHO; text++; }
return{ws}*;	{ printf("return;"); text++; }
{kw}{ws}+	{ 
			while (yytext[yyleng-1] == ' '|| yytext[yyleng-1] == '\t')
				yytext[--yyleng]='\0';
			if (debug)
				printf("!kw!%s ", yytext);
			else
				printf("%s ", yytext);
			text++;
		}
\'([^\'\n]*[\\][\']*)*[^\'\n]*\'	{ ECHO; text++; /* single quoted string */}
\"([^\"\n]*[\\][\"]*)*[^\"\n]*\"	{ ECHO; text++; /* double quoted string */}
[/][^/ \t\n]*[/]	{ ECHO; text++; /* slash delimited string. May NOT contain white-space */}
[/][/].*$	{ if (!inJS) { ECHO; text++; } /* comment to EOL */ }
[/][*]		{ if (inJS) skipcmnts(); else { ECHO; text++; } /* C style (old school) comment */ }
^[ \t]+		;
{ws}+		{ if (!inJS) { printf(" "); text++; } }
[\n]		{ if (text) printf("\n"); text = 0; }
{tag}+		{ if (debug) printf("!tag!%s", yytext);
		else ECHO;
		text++; }
{punc}+		{ if (debug) printf("!P!%s", yytext);
		else ECHO;
		text++; }
.		{ if (debug) printf("!!%s", yytext);
		else ECHO;				/* catch all */
		text++; }
%%
skipcmnts()
{
	register int c;
	for(;;)
	{
		while ((c = input()) != '*' && c != EOF);
		if (c == '*')
		{
			while ((c = input()) == '*');
			if (c == '/')
				break;    /* found the end */
		}
		if (c == EOF)
		{
			error("EOF in comment");
			break;
		}
	}
}

main(int argc, char **argv)
{
	int i;
	for (i = 1; i < argc; i++)
	{
		if (strcmp(argv[i], "js=1") == 0)
			inJS = 1;
		else if (strcmp(argv[i], "js=0") == 0)
			inJS = 0;
		else if (strcmp(argv[i], "debug=1") == 0)
			debug = 1;
		else if (strcmp(argv[i], "debug=0") == 0)
			debug = 0;
		else
		{
			printf("usage: %s [js=1] [debug=1] < file\n", argv[0]);
			exit(1);
		}
	}
	while (yylex());
}
