#ifndef _SEND_ADDR_H
#define _SEND_ADDR_H

#include <net/if.h>
#include <netinet/in.h>

#include <cga.h>
#include <list.h>
#include <hashtbl.h>
#include "misc.h"

#define IF_INDEX_SIZE 32

struct s_iface {
  struct list_head head;
  char name[IF_NAMESIZE+1];
	unsigned int ifi;
  unsigned int mtu;
  unsigned int flags;
  int send_enabled;
  //... counters;  
  void *os_data;
};

struct s_iface_list {
  struct s_ptr_index index;
  struct list_head list;
};

struct s_ip6addr {
	htbl_item_t	hit;
  struct list_head head;
  struct s_iface *iface;
	struct in6_addr addr;
  struct in6_addr prefix;
	int prefix_len;
	uint32_t prefix_vltime;
	uint32_t prefix_pltime;
  //unsigned int scope;
	unsigned int flags;
	char saddr[INET6_ADDRSTRLEN];
  struct snd_cga_params *cga_params;
  void *os_data;
};

struct s_ip6addr_list {
  htbl_t *table;
  struct list_head list;
};

struct snd_ll_addr {
	struct in6_addr	addr;
	int		ifi;
	struct list_head list;
};

/* shared between addr.c and net.c */
extern struct s_iface_list ifaces; 
extern struct s_ip6addr_list ip6addrs;

int snd_replace_this_non_cga_linklocal(struct in6_addr *a, int ifi);
int snd_replace_non_cga_linklocals();
int snd_iface_ok(int ifi);
struct s_ip6addr *find_ip6addr(struct in6_addr *a, int ifi);
int snd_enable_iface(const char *name);
void snd_enable_all();
void snd_dump_ifaces();
int snd_addr_init();
int snd_addr_free();

#endif /* _SEND_ADDR_H */
