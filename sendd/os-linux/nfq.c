#include <netinet/in.h>
#include <linux/netfilter.h> 
#include <libnetfilter_queue/libnetfilter_queue.h>

#include "config.h"
#include <applog.h>

#include "nfq.h"
#include "../os_specific.h"
#include "../sendd_local.h"
#include "snd_linux.h"

#ifdef DEBUG
#include "../dbg.h"

static struct dlog_desc dbg_nfq = {
	.desc =	"nf_queue",
	.ctx =	SND_OS_NAME
};
#endif

static struct nf_queue nf_q = {
  .fd = -1,
  .num = -1,
  .h = NULL,
  .qh = NULL
};

/* Process information of queued packet */
static inline void nfq_process_data(struct nfq_data *nfa, struct sbuff *b)
{
	unsigned int in;
  u_int32_t ifi;

  b->len = nfq_get_payload(nfa, &(b->data));

	if ((ifi = nfq_get_indev(nfa)) > 0) {
		in = 1;
	} else if ((ifi = nfq_get_outdev(nfa)) > 0) {
		in = 0;
	} else {
		applog(LOG_ERR, "%s: pkt has neither indev nor outdev", __FUNCTION__);
    //???: nfq_set_verdict(nf_q.qh, ph->packet_id, NF_DROP, 0, NULL);
    //???: add packet_id to sbuff?
    return;
	}

	snd_recv_pkt(b, ifi, in, nfa);
}

static inline void nfq_recv()
{
  int r;
  char buf[SND_NFQ_BUFF_LEN] __attribute__ ((aligned));
  
  if ((r = recv(nf_q.fd, buf, sizeof(buf), MSG_DONTWAIT)) < 0) {
    applog(LOG_ERR, "%s: recv()", __FUNCTION__);
    return;
  } else if (r == 0) {
    return; /* No data */
  } else {
    nfq_handle_packet(nf_q.h, buf, r);
  }
}

/* Callback when packet is received */
static int nfq_recv_pkt(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
                        struct nfq_data *nfa, void *data)
{
  /*int r;*/
  struct sbuff *b = snd_get_buf();

  if (b == NULL) {
    return FAILURE;
  }
  
#ifdef DEBUG
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
  if (!ph) {
    applog(LOG_ERR, "%s: nfq_data has no header", __FUNCTION__);
    goto fail;
  }
  
  DBG(&dbg_nfq, "Received packet id=%d from queue", ntohl(ph->packet_id));
#endif

  nfq_process_data(nfa, b);

#ifdef DEBUG
fail:
#endif
  snd_put_buf(b);
  return SUCCESS;  
}

int linux_nfq_init(int q_num)
{
#ifdef DEBUG
  struct dlog_desc *dbgs[] = {
  	&dbg_nfq,
  	NULL
  };
  
  if (snd_applog_register(dbgs) < 0) {
  	return FAILURE;
  }
#endif

  /* Opening library handle */
  if ((nf_q.h = nfq_open()) == NULL) {
    applog(LOG_ERR, "%s: nfq_open() failed", __FUNCTION__);
    return FAILURE;
  }
  
  /* Unbinding existing nf_queue handler for AF_INET6 (if any) */
  if (nfq_unbind_pf(nf_q.h, AF_INET6) < 0) {
    applog(LOG_ERR, "%s: nfq_unbind_pf() failed", __FUNCTION__);
    return FAILURE;
  }

  /* Binding nfnetlink_queue as nf_queue handler for AF_INET6 (if any) */
  if (nfq_bind_pf(nf_q.h, AF_INET6) < 0) {
    applog(LOG_ERR, "%s: nfq_bind_pf() failed", __FUNCTION__);
    return FAILURE;
  }
  
  /* Binding this socket to queue number [q_num] */
  if ((nf_q.qh = nfq_create_queue(nf_q.h,  q_num, &nfq_recv_pkt, NULL)) == NULL) {
    applog(LOG_ERR, "%s: nfq_create_queue() failed", __FUNCTION__);
    return FAILURE;
  }
  nf_q.num = q_num;

  /* Setting copy_packet mode */
  if (nfq_set_mode(nf_q.qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
    applog(LOG_ERR, "%s: nfq_set_mode() failed", __FUNCTION__);
    return FAILURE;
  }
  
  nf_q.fd = nfq_fd(nf_q.h);
  
  DBG(&dbg_nfq, "success");
  return SUCCESS;
}

int linux_nfq_free()
{
  int r = SUCCESS;
  
  /* Unbinding from queue */
  if (nf_q.qh && (r = nfq_destroy_queue(nf_q.qh) != SUCCESS)) {
    applog(LOG_ERR, "%s: nfq_destroy_queue() failed", __FUNCTION__);
    //return (-1);
  } else {
    nf_q.qh = NULL;
  }
  
  /* Closing library handle */
  if (nf_q.h && (r = nfq_close(nf_q.h) != SUCCESS)) {
    applog(LOG_ERR, "%s: nfq_close() failed", __FUNCTION__);
    //return (-1);
  } else {
    nf_q.h = NULL;
  }
  
  DBG(&dbg_nfq, "%s", (r == SUCCESS) ? "success" : "failure");
  return r;
}

void linux_nfq_add_fds(fd_set *fds, int *maxfd)
{
  FD_SET(nf_q.fd, fds);
  *maxfd = sendd_max(*maxfd, nf_q.fd);
}

void inline linux_nfq_serve_fds(fd_set *fds)
{
  if (FD_ISSET(nf_q.fd, fds)) {
    nfq_recv();
  }
}

void linux_nfq_deliver_pkt(void *p, struct sbuff *b, int drop, int changed)
{
	struct nfq_data *nfa = p;
	void *newpkt = NULL;
	int plen = 0;
  int r;
  
  struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
  if (!ph) {
    applog(LOG_ERR, "%s: nfq_data has no header", __FUNCTION__);
    return;
  }

  DBG(&dbg_nfq, "%s %spacket id=%d", drop ? "Dropping" : "Delivering", changed ? "changed " : "", ntohl(ph->packet_id));

	if (changed && !drop) {
		newpkt = sbuff_data(b);
		plen = b->len;

    DBG_HEXDUMP(&dbg_nfq, "packet data:", newpkt, plen);
	}

	if ((r = nfq_set_verdict(nf_q.qh, ntohl(ph->packet_id), drop ? NF_DROP : NF_ACCEPT,	plen, newpkt)) < 0)  {
    applog(LOG_ERR, "%s: nfq_set_verdict returns %d", __FUNCTION__, r);
  }
}
