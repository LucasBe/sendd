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

#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "config.h"
#include <applog.h>
#include <hashtbl.h>
#include <list.h>

#include "sendd_local.h"
#include "snd_config.h"
#include "os_specific.h"
#include "os/os_defines.h"
#include "dbg.h"
#include "addr.h"
#include "misc.h"

#ifdef	DEBUG
#include <arpa/inet.h>
static char abuf[INET6_ADDRSTRLEN];

static struct dlog_desc dbg = {
	.desc = "addr",
	.ctx = SENDD_NAME
};
#endif

struct s_iface_list ifaces = {
  .list = { &(ifaces.list), &(ifaces.list) } /* LIST_HEAD_INIT(list)*/
};

struct s_ip6addr_list ip6addrs = {
  .list = { &(ip6addrs.list), &(ip6addrs.list) } /* DEFINE_LIST_HEAD(ip6addrs) */
};

static DEFINE_LIST_HEAD(snd_non_cga_linklocals);

static int do_replace_linklocal(struct in6_addr *old, struct in6_addr *new, int ifi)
{
	DBG(&dbg, "replacing %s",
	    inet_ntop(AF_INET6, old, abuf, sizeof (abuf)));

	if (os_specific_del_addr(old, ifi, 64) < 0 ||
	    os_specific_add_addr(new, ifi, 64, SND_LIFE_INF, SND_LIFE_INF)
	    < 0) {
		return (-1);
	}

	return (0);
}

static int gen_linklocal_cga(struct in6_addr *addr, int ifi)
{
	struct snd_cga_params *p;

	if ((p = snd_find_params_byifidx(ifi)) == NULL) {
		return (-1);
	}

	/* set link local prefix */
	memset(addr, 0, sizeof (*addr));
	addr->s6_addr32[0] = htonl(0xfe800000);

	/* Generate same link-local for all interfaces */
	if (snd_cga_gen(addr, p) < 0) {
		DBG(&dbg, "snd_cga_gen() failed");
		return (-1);
	}
	DBG(&dbg, "generated address: %s",
	    inet_ntop(AF_INET6, addr, abuf, sizeof (abuf)));

	return (0);
}

/*
 * Since this is a user-space only implementation, we can't modify
 * how the kernel forms link-locals when it initializes the IPv6
 * stack. Instead, when this daemon starts up, we replace all non-CGA
 * link-locals with a CGA link-local. We re-use the same one so that
 * we won't need to find a new modifier for each address (this is the
 * same as for address autoconfiguration).
 */
/*static int replace_linklocals()
{
	struct snd_ll_addr *ap, *n;
	struct in6_addr addr[1];

	list_for_each_entry_safe(ap, n, &snd_non_cga_linklocals, list) {
		if (gen_linklocal_cga(addr, ap->ifi) < 0) {
			return (-1);
		}
#ifdef DEBUG
    if (do_replace_linklocal(&ap->addr, addr, ap->ifi) < 0)
      DBG(&dbg, "do_replace_linklocal() failed");
#else
		do_replace_linklocal(&ap->addr, addr, ap->ifidx);
#endif
		list_del(&ap->list);
		free(ap);
	}

	return (0);
}*/

/*static void add_ll_addr(struct in6_addr *a, int ifi)
{
	struct snd_ll_addr *ap;

	if ((ap = malloc(sizeof (*ap))) == NULL) {
		APPLOG_NOMEM();
		return;
	}
	memcpy(&ap->addr, a, sizeof (ap->addr));
	ap->ifi = ifi;
	list_add(&ap->list, &snd_non_cga_linklocals);
}*/

int snd_replace_this_non_cga_linklocal(struct in6_addr *a, int ifi)
{
	struct in6_addr cga_addr[1];

	if (!snd_conf_get_int(snd_replace_linklocals)) {
		return SUCCESS;
	}
	if (gen_linklocal_cga(cga_addr, ifi) < 0 ||
	    do_replace_linklocal(a, cga_addr, ifi) < 0) {
		return FAILURE;
	}

	return SUCCESS;
}

int snd_replace_non_cga_linklocals()
{
	struct s_ip6addr *addr;
	struct in6_addr cga_addr[1];

	if (!snd_conf_get_int(snd_replace_linklocals))
    return SUCCESS;

	list_for_each_entry(addr, &ip6addrs.list, head) {
    if(addr->iface) {
    	DBG(&dbg, "%s/%d (%d)", addr->saddr, addr->prefix_len, addr->iface->ifi);
      if(!addr->iface->send_enabled) {
        DBG(&dbg, "SEND on interface %d is not enabled, skipping", addr->iface->ifi);
        continue;
      }
      
      if (addr->cga_params) {
    		DBG(&dbg, "address is already CGA, skipping");
    		continue;
       }        
  
    	if (IN6_IS_ADDR_LOOPBACK(&addr->addr)) {
    		DBG(&dbg, "address is loopback, skipping");
    		continue;
    	}
    
    	if (addr->prefix_len != 64) {
    		DBG(&dbg, "prefix length != 64 bits, skipping");
    		continue;
    	}	
      if (gen_linklocal_cga(cga_addr, addr->iface->ifi) < 0) {
        DBG(&dbg, "gen_linklocal_cga() failed");
  			continue;
  		}
#ifdef DEBUG
      if (do_replace_linklocal(&addr->addr, cga_addr, addr->iface->ifi) < 0)
        DBG(&dbg, "do_replace_linklocal() failed");
#else
  		do_replace_linklocal(&addr->addr, cga_addr, addr->iface->ifi);
#endif
    }
#ifdef DEBUG
    else {DBG(&dbg, "address is not linked to interface");}
#endif
	}

	return SUCCESS;
}

//static void snd_cfg_addr(struct in6_addr *a, int plen, int ifi)
/*static void snd_cfg_addr(struct s_ip6addr *addr)
{
	DBG(&dbg, "%s/%d (%d)", addr->saddr, addr->prefix_len, addr->iface->ifi);

	if (IN6_IS_ADDR_LOOPBACK(&addr->addr)) {
		DBG(&dbg, "skipping loopback");
		return;
	}

	if (addr->prefix_len != 64) {
		DBG(&dbg, "prefix length != 64 bits; skipping");
		return;
	}

	if (!snd_is_lcl_cga(&addr->addr, addr->iface->ifi)) {
		DBG(&dbg, "not CGA");
		if (snd_conf_get_int(snd_replace_linklocals) && IN6_IS_ADDR_LINKLOCAL(&addr->addr)) {
			add_ll_addr(&addr->addr, addr->iface->ifi);
		}
		return;
	}
}*/

/*static int get_addrs()
{
	FILE *fp;
	struct in6_addr a;
	uint32_t ifi, plen, scope, flags;
	char buf[128], ifname[32];
	int i, off, digit;

	if ((fp = fopen("/proc/net/if_inet6", "r")) == NULL) {
		applog(LOG_ERR, "%s: fopen(/proc/net/if_inet6): %s",
		       __FUNCTION__, strerror(errno));
		return (-1);
	}

	while (fgets(buf, sizeof (buf), fp) != NULL) {
		for (i = off = 0; i < 16; i++, off += 2) {
			sscanf(buf + off, "%02x", &digit);
			a.s6_addr[i] = digit;
		}
		sscanf(buf + off, "%02x %02x %02x %02x %32s\n",
		       &ifi, &plen, &scope, &flags, ifname);
		snd_cfg_addr(&a, plen, ifi);
	}

	fclose(fp);
	return (0);
}*/

int snd_iface_ok(int ifi)
{
  struct s_iface *iface;
  
  if ((iface = ptr_index_get(&ifaces.index, ifi)) != NULL)
    return iface->send_enabled;

	return FALSE;
}

int snd_enable_iface(const char *name)
{
	struct s_iface *iface;
	int ifi;
  struct list_head *iface_head = &ifaces.list;

	if ((ifi = if_nametoindex(name)) == 0) {
		applog(LOG_ERR, "invalid interface: %s", name);
		return FAILURE;
	}

  if ((iface = ptr_index_get(&ifaces.index, ifi)) == NULL) {
    /* sorted insert */
    list_for_each_entry(iface, &ifaces.list, head) {
      if (iface->ifi > ifi) {
        iface_head = &iface->head;
        break;
      }
  	}
  
    if ((iface = malloc(sizeof(struct s_iface))) == NULL) {
    	APPLOG_NOMEM();
    	return FAILURE;
    }
    list_add_tail(&iface->head, iface_head);
    iface->ifi = ifi;
    strncpy(iface->name, name, IF_NAMESIZE+1);
    ptr_index_set(&ifaces.index, iface->ifi, iface); /* update index */
  }
  iface->send_enabled = TRUE;
  DBG(&dbg, "SEND enabled on interface %d", ifi);

  return SUCCESS;    
}

void snd_enable_all()
{
  struct s_iface *iface;
  list_for_each_entry(iface, &ifaces.list, head) {
    if(iface->flags & IFF_LOOPBACK) {
      DBG(&dbg, "interface %d is loopback, skipping", iface->ifi);
      continue;
    }
    if(iface->flags & IFF_UP) {
      iface->send_enabled = TRUE;
      DBG(&dbg, "SEND enabled on interface %d", iface->ifi);
    } else {
      DBG(&dbg, "interface %d is not UP, skipping", iface->ifi);
    }
	}  
}

void snd_dump_ifaces()
{
	struct s_iface *iface;

	list_for_each_entry(iface, &ifaces.list, head) {
		printf("\t  %d:%-17s%s%s%s\n", iface->ifi, iface->name,
      iface->flags & IFF_UP ? "up " : "",
      iface->flags & IFF_LOOPBACK ? "loopback " : "",
      iface->send_enabled ? "send" : "");
	}
}

static inline int ifaces_init(struct s_iface_list *ifaces)
{
	if (ptr_index_init(&ifaces->index, IF_INDEX_SIZE) != SUCCESS) {
    //DBG(&dbg, "ptr_index_init() failed");
    return FAILURE;
  }
  return SUCCESS;  
}

static inline int ifaces_free(struct s_iface_list *ifaces)
{
	struct s_iface *if_p, *if_tmp;

	list_for_each_entry_safe(if_p, if_tmp, &ifaces->list, head) {
		list_del(&if_p->head);
		free(if_p);
	}

  ptr_index_free(&ifaces->index);

  return SUCCESS;
}

static uint32_t hash_ip6addr(void *a, int sz)
{
	struct s_ip6addr *p = a;
	return (hash_in6_addr(&p->addr, sz));
}

static int match_ip6addr(void *a, void *b)
{
	struct s_ip6addr *x = a;
	struct s_ip6addr *y = b;

  if (x->iface != NULL && y->iface != NULL) {
  	if (x->iface->ifi != y->iface->ifi) {
  		return (x->iface->ifi - y->iface->ifi);
  	}
  } else if (x->iface == NULL && y->iface != NULL) {
    return -y->iface->ifi;
  } else if (x->iface != NULL && y->iface == NULL) {
    return x->iface->ifi;
  }

	return (memcmp(&x->addr, &y->addr, sizeof (x->addr)));
}

struct s_ip6addr *find_ip6addr(struct in6_addr *a, int ifi)
{
	struct s_ip6addr k[1];
	k->addr = *a;
	k->iface = ptr_index_get(&ifaces.index, ifi);
	return htbl_find(ip6addrs.table, k);
}

static inline int ip6addrs_init(struct s_ip6addr_list *addrs)
{
	if ((addrs->table = htbl_create(SND_HASH_SZ, hash_ip6addr, match_ip6addr)) == NULL) {
		DBG(&dbg, "htbl_create() failed");
		return FAILURE;
	}
  
  return SUCCESS;
}

static inline int ip6addrs_free(struct s_ip6addr_list *addrs)
{
  struct s_ip6addr *addr_p, *addr_tmp;

	list_for_each_entry_safe(addr_p, addr_tmp, &addrs->list, head) {
		list_del(&addr_p->head);
		free(addr_p);
	}

  if (addrs->table) htbl_destroy(addrs->table, NULL);

  return SUCCESS;
}
int snd_addr_init()
{
#ifdef	DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg,
		NULL
	};

	if (snd_applog_register(dbgs) < 0) {
		return FAILURE;
	}
#endif

  if(ifaces_init(&ifaces) != SUCCESS) {
    DBG(&dbg, "ifaces_init() failed");
    return FAILURE;
  }  

  if(ip6addrs_init(&ip6addrs) != SUCCESS) {
    DBG(&dbg, "ip6addrs_init() failed");
    return FAILURE;
  }  

  if(os_get_ifaces() != SUCCESS) {
    DBG(&dbg, "os_get_ifaces() failed");
    return FAILURE;
  }

	if (os_get_addrs() != SUCCESS) {
    DBG(&dbg, "get_addrs() failed");
    return FAILURE;
  }
  
  DBG(&dbg, "success");
  return SUCCESS;
}

int snd_addr_free()
{
  ip6addrs_free(&ip6addrs);
  ifaces_free(&ifaces);

  DBG(&dbg, "success");
  return SUCCESS;
}
