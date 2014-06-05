#include <linux/netlink.h>

#include <list.h>

int linux_net_init();
int linux_net_free();
int linux_get_ifaces();
int linux_get_addrs();
int linux_add_addr(struct in6_addr *a, int ifi, int plen, uint32_t vlife, uint32_t plife);
int linux_del_addr(struct in6_addr *a, int ifidx, int plen);
int net_handle_msg(struct nl_msg *);
