#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <errno.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include "config.h"
#include <applog.h>

#include "netlink.h"
#include "../os_specific.h"
#include "../sendd_local.h"
#include "snd_linux.h"
#include "net.h"

#ifdef	DEBUG
#include "../dbg.h"
static struct dlog_desc dbg_nl = {
	.desc = "netlink",
	.ctx = SND_OS_NAME
};
#endif

static struct s_nl nl = {
  .fd = -1,
  .seq = 0,
  .exp_seq = 0,
};

int linux_nl_init()
{

#ifdef DEBUG
  struct dlog_desc *dbgs[] = {
  	&dbg_nl,
  	NULL
  };
  
  if (snd_applog_register(dbgs) < 0) {
  	return FAILURE;
  }
#endif

	memset(&nl.sock_addr, 0, sizeof(nl.sock_addr));
	nl.sock_addr.nl_groups = RTMGRP_LINK | RTMGRP_IPV6_IFADDR;
  nl.sock_addr.nl_family = AF_NETLINK;

  /* Opening netlink socket */
	if ((nl.fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE)) == -1) {
    applog(LOG_ERR, "%s: socket() failed", __FUNCTION__);
		return FAILURE;
  }
	
  /* Binding netlink socket */
	if (bind(nl.fd, (struct sockaddr *)&nl.sock_addr, sizeof(nl.sock_addr)) == -1) {
    applog(LOG_ERR, "%s: bind() failed", __FUNCTION__);
		return FAILURE;
  }

  DBG(&dbg_nl, "success");
  return SUCCESS;
}

void linux_nl_add_fds(fd_set *fds, int *maxfd)
{
  FD_SET(nl.fd, fds);
  *maxfd = sendd_max(*maxfd, nl.fd);
}

void inline linux_nl_serve_fds(fd_set *fds)
{
  if (FD_ISSET(nl.fd, fds)) {
    nl_handle_fd();
  }
}

int linux_nl_free()
{
  if (nl.fd != -1 && close(nl.fd) == -1) {
    applog(LOG_ERR, "%s: close() failed", __FUNCTION__);
    return FAILURE;
  }
  
  DBG(&dbg_nl, "success");
  return SUCCESS;
}

int nl_msg_init(struct nl_msg *msg)
{
  if ((msg->hdr = calloc(1, sizeof(struct nlmsghdr))) == NULL)
  {
    msg->buff = NULL;
    msg->buff_len = msg->msg_len = 0;
    return FAILURE;
  }
  msg->buff = (void *)msg->hdr;
  msg->buff_len = msg->msg_len = sizeof(struct nlmsghdr);
  return SUCCESS;
}

int nl_msg_read_clear(struct nl_msg *msg)
{
  if (msg->msg_len) {
    for (; NLMSG_OK(msg->hdr, msg->msg_len); msg->hdr = NLMSG_NEXT(msg->hdr, msg->msg_len)) 
      nl_handle_type(msg);
  }
  return nl_msg_clear(msg);  
}

int nl_msg_clear(struct nl_msg *msg)
{
  msg->msg_len = 0;
  msg->buff_len = 0;
  free(msg->buff);
  return SUCCESS;
}

int nl_msg_assign(struct nl_msg *msg_ptr, void *msg_data, ssize_t len)
{
  msg_ptr->buff = msg_data;
  msg_ptr->hdr = (struct nlmsghdr *)msg_ptr->buff;
  msg_ptr->buff_len = msg_ptr->msg_len = len;
  return SUCCESS;
}

int nl_add_rta(struct nlmsghdr *n, unsigned int maxlen, int type, const void *data, int alen)
{
	int len = RTA_LENGTH(alen);
	struct rtattr *rta;

	if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > maxlen) {
		errno = ENOBUFS;
		return FAILURE;
	}

	rta = ((struct rtattr *)(((ptrdiff_t)(n))+NLMSG_ALIGN((n)->nlmsg_len)));
	rta->rta_type = type;
	rta->rta_len = len;
	memcpy(RTA_DATA(rta), data, alen);
	n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);

	return SUCCESS;
}

int nl_recv(struct nl_msg *msg, int flags)
{
  struct iovec iov;
  struct msghdr msg_hdr;
  struct sockaddr_nl source;
  char *buff_new;

  /* Reset message header pointer */
  msg->hdr = (struct nlmsghdr *)msg->buff;

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = msg->buff;
  iov.iov_len = msg->buff_len;  

  memset(&msg_hdr, 0, sizeof(msg_hdr));
  msg_hdr.msg_name = &source;
  msg_hdr.msg_namelen = sizeof(source);
  msg_hdr.msg_iov = &iov;
  msg_hdr.msg_iovlen = 1;
  
  for (;;)
  {
    /* Look, how long is response ... */
    msg->msg_len = recvmsg(nl.fd, &msg_hdr, flags | MSG_DONTWAIT | MSG_PEEK | MSG_TRUNC);
    if (msg->msg_len == -1)
    {
			if (errno == EAGAIN) {
        DBG(&dbg_nl, "peeking: %s", strerror(errno));
      	return FAILURE;
			}
			if (errno == EINTR) {
				continue;
      }
    	return FAILURE;
		} 
    else if (msg->msg_len == msg->buff_len)
    {
			/* Support kernels older than 2.6.22 */
			if (msg->msg_len == 0)
				msg->msg_len = SND_NL_RECV_BUFF_LEN;
			else
				msg->msg_len *= SND_NL_RECV_BUFF_INC;
		}
		if (msg->buff_len < msg->msg_len) 
    {
			/* Alloc 1 more so we work with older kernels */
			msg->buff_len = msg->msg_len + 1;
			buff_new = realloc(msg->buff, msg->buff_len);
			if (buff_new == NULL) {
      	return FAILURE;
      }
			msg->buff = buff_new;
      msg->hdr = (struct nlmsghdr *)msg->buff;
      //DBG(&dbg_nl, "%s: realloc: buff_len=%d, msg_len=%d", __FUNCTION__, msg->buff_len, msg->msg_len);
      iov.iov_base = msg->buff;
      iov.iov_len = msg->buff_len;  
		}
    
    /* Receive response ... */
    msg->msg_len = recvmsg(nl.fd, &msg_hdr, flags);
		if (msg->msg_len == -1)
    {
			if (errno == EAGAIN) {
        DBG(&dbg_nl, "reading: %s", strerror(errno));
      	return FAILURE;
			}
			if (errno == EINTR)
				continue;
    	return FAILURE;
		}

		/* Check sender */
		/*if (msg_hdr.msg_namelen != sizeof(nladdr)) {
			errno = EINVAL;
      DBG(&dbg_nl, strerror(errno));
    	//free(buf);
    	return FAILURE;
		}*/
    
		/* Ignore message if it is not from kernel */
		if (source.nl_pid != 0) {
      DBG(&dbg_nl, "message is NOT from kernel");
			continue;
    }
    
    /*if (msg->hdr->nlmsg_seq != nl.exp_seq) {
      DBG(&dbg_nl, "message out of order (expecting %d got %d)", nl.exp_seq++, msg->hdr->nlmsg_seq);
      return FAILURE;
    }*/
    
    //DBG(&dbg_nl, "expecting %d got %d", nl.exp_seq++, msg->hdr->nlmsg_seq);
    return SUCCESS;
  }
}

int nl_send(struct nl_msg *msg, int flags)
{
  int r = FAILURE;
  struct iovec iov;
  struct msghdr msg_hdr;
  struct nl_msg answer;
  
  if(nl_msg_init(&answer) != SUCCESS)
    return FAILURE;

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = msg->hdr;
  iov.iov_len = msg->hdr->nlmsg_len;
  
  memset(&msg_hdr, 0, sizeof(msg_hdr));
  msg_hdr.msg_name = &nl.sock_addr; /* Source is our netlink socket */
  msg_hdr.msg_namelen = sizeof(nl.sock_addr);
  msg_hdr.msg_iov = &iov;
  msg_hdr.msg_iovlen = 1;
  /* Request a reply */
  msg->hdr->nlmsg_flags |= NLM_F_ACK;
  msg->hdr->nlmsg_seq = ++(nl.seq);
  nl.exp_seq = 0;

  //DBG(&dbg_nl, "expecting %d", nl.exp_seq);
  if (sendmsg(nl.fd, &msg_hdr, flags) < 0) {
    DBG(&dbg_nl, "sendmsg() failed");
    goto end;
  }  
  if (nl_recv(&answer, 0) != SUCCESS) {
    DBG(&dbg_nl, "nl_recv() failed");
    goto end;
  }   
  if(nl_error(&answer) == FAILURE) {
    DBG(&dbg_nl, "nl_error() failed");
    goto end;     
  }  
  r = SUCCESS;
end:  
  nl_msg_clear(&answer);
  return r;
}

int nl_talk(struct nl_msg *request, int send_flags, struct nl_msg *answer, int recv_flags)
{
  int r = FAILURE;
  struct iovec iov;
  struct msghdr msg;

  memset(&iov, 0, sizeof(iov));
  iov.iov_base = request->hdr;
  iov.iov_len = request->hdr->nlmsg_len;
  
  memset(&msg, 0, sizeof(msg));
  msg.msg_name = &nl.sock_addr; /* Source is our netlink socket */
  msg.msg_namelen = sizeof(nl.sock_addr);
  msg.msg_iov = &iov;
  msg.msg_iovlen = 1;
  /* Request a reply */
  request->hdr->nlmsg_flags |= NLM_F_ACK;
  request->hdr->nlmsg_seq = ++(nl.seq);
  nl.exp_seq = 0;
  
  if (sendmsg(nl.fd, &msg, send_flags) < 0) {
    DBG(&dbg_nl, "sendmsg() failed");
    goto end;
  }
  if (nl_recv(answer, recv_flags) != SUCCESS) {
    DBG(&dbg_nl, "nl_recv() failed");
    goto end;    
  }
  if (nl_error(answer) != SUCCESS) {
    DBG(&dbg_nl, "nl_error() failed");
    goto end;     
  }   
  r = SUCCESS;

end:  
  return r;
}

int nl_error(struct nl_msg *msg)
{
	struct nlmsgerr *err;
	int len;

  if(msg->hdr->nlmsg_type != NLMSG_ERROR)
    return SUCCESS;
	len = msg->hdr->nlmsg_len - sizeof(struct nlmsghdr);
	if ((size_t)len < sizeof(*err)) {
		errno = EBADMSG;
    DBG(&dbg_nl, strerror(errno));
		return FAILURE;
	}
	err = (struct nlmsgerr *)NLMSG_DATA(msg->hdr);
	if (err->error == 0) {
    //DBG(&dbg_nl, "returns %d", len);
    //msg->hdr = NLMSG_NEXT(msg->hdr, msg->msg_len);
		return SUCCESS;
  }
	errno = -err->error;
  DBG(&dbg_nl, strerror(errno));
	return FAILURE;  
}

/*int nl_error(struct nl_msg *msg)
{
	if (msg->hdr->nlmsg_type != NLMSG_ERROR)
		return SUCCESS;
  return nl_error_hdr(msg->hdr);
}*/

/*int nl_wait_type(int msg_type, struct nl_msg *msg, int flags)
{
  while(1) {
    DBG(&dbg_nl, "waiting for type %d", msg_type);
    if(nl_recv(msg, flags) != SUCCESS)
      return FAILURE;
    if (msg->msg_len)
    {
      for (; NLMSG_OK(msg->hdr, msg->msg_len); msg->hdr = NLMSG_NEXT(msg->hdr, msg->msg_len)) {
        if(msg->hdr->nlmsg_type == msg_type) {
          // We have got what we were waiting for 
          return SUCCESS;
        } else {
          if (nl_handle_type(msg) == FAILURE)
            return FAILURE;
        }
      }
    }
    else return FAILURE;
  }  
}*/

int nl_handle_type(struct nl_msg *msg)
{
  if(msg->hdr->nlmsg_type >= RTM_BASE && msg->hdr->nlmsg_type <= RTM_MAX) {
    net_handle_msg(msg);  
  } else {
    switch(msg->hdr->nlmsg_type) {
    	case NLMSG_NOOP:		/* Nothing */
    	  break;
      case NLMSG_ERROR:   /* Error */
        return nl_error(msg);
        //break;
      case NLMSG_DONE:    /* End of dump */
        DBG(&dbg_nl, "end of dump");
        break;
      case NLMSG_OVERRUN: /* Data lost */
        DBG(&dbg_nl, "data lost");
        return FAILURE;
        //break;
    	default:
    	  DBG(&dbg_nl, "message type %d unsupported", msg->hdr->nlmsg_type);
        //printf("message type %d, length %d\n", msg_ptr->nlmsg_type, msg_ptr->nlmsg_len);
    	  break;
    }
  }
  return SUCCESS;
}

void inline nl_handle_fd()
{
  struct nl_msg msg;

  if(nl_msg_init(&msg) != SUCCESS) {
    DBG(&dbg_nl, "nl_msg_init() failed");
    return;
  }
  if(nl_recv(&msg, 0) != SUCCESS) {
    DBG(&dbg_nl, "nl_recv() failed");
    return;
  }
  if (msg.msg_len) {
    for (; NLMSG_OK(msg.hdr, msg.msg_len); msg.hdr = NLMSG_NEXT(msg.hdr, msg.msg_len)) 
      nl_handle_type(&msg);
  }
  
  nl_msg_clear(&msg);
}
