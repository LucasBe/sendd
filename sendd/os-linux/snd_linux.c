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

#include <netinet/in.h>
#include <sys/select.h>

#include <list.h>
#include "../addr.h"
#include "config.h"
#include "../os_specific.h"
#include "snd_linux.h"
#include "nfq.h"
#include "netlink.h"
#include "net.h"

int os_specific_init(void)
{
	if (linux_rand_init() < 0 ||
	    linux_nfq_init(SND_NFQ_NUM) < 0 ||
      linux_nl_init() < 0 ||
      linux_net_init() < 0) {
		return FAILURE;
	}
	return SUCCESS;
}

void os_specific_fini(void)
{
	linux_nfq_free();
	linux_rand_fini();
  linux_nl_free();
  linux_net_free();
}

void os_specific_add_fds(fd_set *fds, int *maxfd)
{
	linux_nfq_add_fds(fds, maxfd);
  linux_nl_add_fds(fds, maxfd);
}

void os_specific_serve_fds(fd_set *fds)
{
	linux_nfq_serve_fds(fds);
  linux_nl_serve_fds(fds);
}

void os_specific_deliver_pkt(void *p, struct sbuff *b, int drop, int changed)
{
  linux_nfq_deliver_pkt(p, b, drop, changed);
}

int os_specific_handle_iface(const char *ifname, int ifi)
{
	return SUCCESS;
}

int os_specific_add_addr(struct in6_addr *a, int ifi, int plen, uint32_t vlife, uint32_t plife)
{
  return linux_add_addr(a, ifi, plen, vlife, plife);
}

int os_specific_del_addr(struct in6_addr *a, int ifi, int plen)
{
  return linux_del_addr(a, ifi, plen);
}

int os_iface_data_free(void *data)
{
  // TODO
  return SUCCESS;
}

int os_ip6addr_data_free(void *data)
{
  // TODO
  return SUCCESS;
}

int os_get_ifaces()
{
  return linux_get_ifaces();
}

int os_get_addrs()
{
  return linux_get_addrs();
}
