#ifndef _SEND_NF_QUEUE_H
#define _SEND_NF_QUEUE_H

#include "../sendd_local.h"

#define SND_NFQ_BUFF_LEN 4096

struct nf_queue {
  int fd;
  int num;                 /* Queue number */
  struct nfq_handle *h;    /* Library handle */
  struct nfq_q_handle *qh; /* Queue handle */
};

int linux_nfq_init(int q_num);
int linux_nfq_free();
void linux_nfq_add_fds(fd_set *fds, int *maxfd);
void linux_nfq_serve_fds(fd_set *fds);
void linux_nfq_deliver_pkt(void *p, struct sbuff *b, int drop, int changed);

#endif /* _SEND_NF_QUEUE_H */
