#ifndef	_SEND_LINUX_H
#define	_SEND_LINUX_H

#include <netinet/in.h>
#include <sys/select.h>
#include <sbuff.h>

#include <list.h>
#include "../addr.h"

#define SND_OS_NAME "linux"
#define RETRANS_TIMER 1
#define HWADDR_LEN 20

extern void linux_rand_fini();
extern int linux_rand_init();

int os_specific_init();
void os_specific_fini();

void os_specific_add_fds(fd_set *fds, int *maxfd);
void os_specific_serve_fds(fd_set *fds);
void os_specific_deliver_pkt(void *p, struct sbuff *b, int drop, int changed);

int os_specific_handle_iface(const char *ifname, int ifi);

int os_specific_add_addr(struct in6_addr *a, int ifidx, int plen, uint32_t vlife, uint32_t plife);
int os_specific_del_addr(struct in6_addr *a, int ifidx, int plen);

int os_iface_data_free(void *data);
int os_ip6addr_data_free(void *data);

int os_get_ifaces();
int os_get_addrs();

#endif	/* _SEND_LINUX_H */
