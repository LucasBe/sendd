/*
 * Copyright © 2006, DoCoMo Communications Laboratories USA, Inc.,
 *   the DoCoMo SEND Project
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of DoCoMo Communications Laboratories USA, Inc., its
 *    parents, affiliates, subsidiaries, theDoCoMo SEND Project nor the names
 *    of the Project's contributors may be used to endorse or promote products
 *    derived from this software without specific prior written permission.
 *
 *  THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 *  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 *  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 *  ARE DISCLAIMED. IN NO EVENT SHALL DOCOMO COMMUNICATIONS LABORATORIES USA,
 *  INC., ITS PARENTS, AFFILIATES, SUBSIDIARIES, THE PROJECT OR THE PROJECT'S
 *  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 *  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 *  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 *  OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 *  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 *  OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 *  ADVISED OF THE POSSIBILITY OF SUCH DAMAGE."
 */

%{
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "config.h"
#include <applog.h>

#include "y.tab.h"

int params_linecnt = 1;

%}

number	([[:digit:]]{-}[0])[[:digit:]]*
dec-octet	[0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-4][0-9]|25[0-5]
ip4addr 	{dec-octet}\.{dec-octet}\.{dec-octet}\.{dec-octet}

hexdigit	([a-f]|[A-F]|[0-9])
addr1		{hexdigit}{1,4}":"({hexdigit}{1,4}":")*(":"{hexdigit}{1,4})+
addr2		{hexdigit}{1,4}(":"{hexdigit}{1,4})*"::"
addr3		({hexdigit}{1,4}":"){7}{hexdigit}{1,4}

h16		[0-9A-Fa-f]{1,4}
ls32		{h16}:{h16}|{ip4addr}

ip6addr1 ({h16}:){6}{ls32}
ip6addr2 ::({h16}:){5}{ls32}
ip6addr3 ({h16})?::({h16}:){4}{ls32}
ip6addr4 (({h16}:){0,1}{h16})?::({h16}:){3}{ls32}
ip6addr5 (({h16}:){0,2}{h16})?::({h16}:){2}{ls32}
ip6addr6 (({h16}:){0,3}{h16})?::{h16}:{ls32}
ip6addr7 (({h16}:){0,4}{h16})?::{ls32}
ip6addr8 (({h16}:){0,5}{h16})?::{h16}
ip6addr9 (({h16}:){0,6}{h16})?::

ip6addr	{ip6addr1}|{ip6addr2}|{ip6addr3}|{ip6addr4}|{ip6addr5}|{ip6addr6}|{ip6addr7}|{ip6addr8}|{ip6addr9}

%s STRING

%%

<STRING>[^ \t\n;]+ {
	params_lval.string = strdup(yytext);
	BEGIN 0;
	return T_STRING;
}

[Nn]amed	{ BEGIN STRING; return T_NAMED; }
[Aa]ddress	{ return T_ADDR; }
[Uu]se		{ BEGIN STRING; return T_USE; }
snd_cga_params	{ BEGIN STRING; return T_DERFILE; }
snd_cga_priv	{ BEGIN STRING; return T_KEYFILE; }
snd_cga_sec	{ return T_SEC; }
[Ii]nterface	{ BEGIN STRING; return T_INTERFACE; }
snd_sig_meth	{ BEGIN STRING; return T_SIGMETH; }

[\t ]+			{ }
"{"|"}"|";"		{ return *yytext; }
#.*$			{ }
\n			{ params_linecnt++;}

{number} {
	params_lval.num = atoi(yytext); return T_NUMBER;
}

{ip6addr} {
	struct in6_addr addr;
	int i;

	i = inet_pton(AF_INET6, yytext, &addr);
	if (i < 0) {
		applog(LOG_ERR, "Error parsing address %s (line %d): %s",
		    yytext, params_linecnt, strerror(errno));
		return T_BAD_TOKEN;
	}

	params_lval.addr6 = addr;
	return T_IPV6_ADDR;
}
