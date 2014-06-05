/* A Bison parser, made by GNU Bison 3.0.2.  */

/* Bison interface for Yacc-like parsers in C

   Copyright (C) 1984, 1989-1990, 2000-2013 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation, either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.  */

/* As a special exception, you may create a larger work that contains
   part or all of the Bison parser skeleton and distribute that work
   under terms of your choice, so long as that work isn't itself a
   parser generator using the skeleton or a modified version thereof
   as a parser skeleton.  Alternatively, if you modify or redistribute
   the parser skeleton itself, you may (at your option) remove this
   special exception, which will cause the skeleton and the resulting
   Bison output files to be licensed under the GNU General Public
   License without this special exception.

   This special exception was added by the Free Software Foundation in
   version 2.2 of Bison.  */

#ifndef YY_PARAMS_Y_TAB_H_INCLUDED
# define YY_PARAMS_Y_TAB_H_INCLUDED
/* Debug traces.  */
#ifndef YYDEBUG
# define YYDEBUG 0
#endif
#if YYDEBUG
extern int params_debug;
#endif

/* Token type.  */
#ifndef YYTOKENTYPE
# define YYTOKENTYPE
  enum yytokentype
  {
    T_STRING = 258,
    T_IPV6_ADDR = 259,
    T_NAMED = 260,
    T_ADDR = 261,
    T_USE = 262,
    T_SIGMETH = 263,
    T_DERFILE = 264,
    T_KEYFILE = 265,
    T_SEC = 266,
    T_INTERFACE = 267,
    T_BAD_TOKEN = 268,
    T_NUMBER = 269
  };
#endif
/* Tokens.  */
#define T_STRING 258
#define T_IPV6_ADDR 259
#define T_NAMED 260
#define T_ADDR 261
#define T_USE 262
#define T_SIGMETH 263
#define T_DERFILE 264
#define T_KEYFILE 265
#define T_SEC 266
#define T_INTERFACE 267
#define T_BAD_TOKEN 268
#define T_NUMBER 269

/* Value type.  */
#if ! defined YYSTYPE && ! defined YYSTYPE_IS_DECLARED
typedef union YYSTYPE YYSTYPE;
union YYSTYPE
{
#line 94 "params_gram.y" /* yacc.c:1909  */

	char		*string;
	int		num;
	struct in6_addr addr6;

#line 88 "y.tab.h" /* yacc.c:1909  */
};
# define YYSTYPE_IS_TRIVIAL 1
# define YYSTYPE_IS_DECLARED 1
#endif


extern YYSTYPE params_lval;

int params_parse (void);

#endif /* !YY_PARAMS_Y_TAB_H_INCLUDED  */
