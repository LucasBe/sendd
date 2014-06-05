#ifndef _SEND_NETLINK_H
#define _SEND_NETLINK_H

#include <linux/netlink.h>
#include <linux/rtnetlink.h>

//#define SND_NL_DUMMY_BUFF_LEN  0
#define SND_NL_RECV_BUFF_LEN 512
#define SND_NL_RECV_BUFF_INC   2
#define SND_NL_IFADDR_REQ_LEN 64

struct s_nl {
  int fd;
  unsigned int seq;
  unsigned int exp_seq;
  struct sockaddr_nl sock_addr;
};

struct nl_ifaddr_req {
	struct nlmsghdr hdr;
	struct ifaddrmsg ifa;
	char buffer[SND_NL_IFADDR_REQ_LEN];
};

struct nl_gen_req {
  struct nlmsghdr hdr;
  struct rtgenmsg gen;
};

struct nl_msg {
  struct nlmsghdr *hdr;
  void *buff;
  ssize_t msg_len;
  ssize_t buff_len;
};

int linux_nl_init();
int linux_nl_free();
void linux_nl_add_fds(fd_set *fds, int *maxfd);
void linux_nl_serve_fds(fd_set *fds);
int nl_msg_init(struct nl_msg *msg);
int nl_msg_read_clear(struct nl_msg *msg);
int nl_msg_clear(struct nl_msg *msg);
int nl_msg_assign(struct nl_msg *msg_ptr, void *msg_data, ssize_t len);
int nl_add_rta(struct nlmsghdr *n, unsigned int maxlen, int type, const void *data, int alen);
int nl_send(struct nl_msg *msg, int flags);
int nl_recv(struct nl_msg *msg, int flags);
int nl_talk(struct nl_msg *request, int send_flags, struct nl_msg *answer, int recv_flags);
int nl_error(struct nl_msg *msg);
//int nl_wait_type(int msg_type, struct nl_msg *msg, int flags);
int nl_handle_type(struct nl_msg *msg);
void nl_handle_fd();


#endif /* _SEND_NETLINK_H */
