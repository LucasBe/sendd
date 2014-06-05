/*
 * Important comment from linux/if_addr.h:
 * IFA_ADDRESS is prefix address, rather than local interface address.
 * It makes no difference for normally configured broadcast interfaces,
 * but for point-to-point IFA_ADDRESS is DESTINATION address,
 * local address is supplied in IFA_LOCAL attribute.
 */

#include <unistd.h>
#include <arpa/inet.h>

#include "config.h"
#include <applog.h>
#include <list.h>
#include <cga.h>

#include "../sendd_local.h"
#include "../addr.h"
#include "netlink.h"
#include "net.h"
#include "snd_linux.h"

#ifdef DEBUG
#include "../dbg.h"

static struct dlog_desc dbg_net = {
	.desc =	"net",
	.ctx =	SND_OS_NAME
};
#endif

int linux_net_init()
{
#ifdef DEBUG
	struct dlog_desc *dbgs[] = {
		&dbg_net,
		NULL
	};
	if (snd_applog_register(dbgs) < 0) {
		return FAILURE;
	}
#endif
  DBG(&dbg_net, "success");
  return SUCCESS;
}

int linux_net_free()
{
  
  DBG(&dbg_net, "success");
  return SUCCESS;
}

static int linux_handle_iface(struct nl_msg *iface_msg)
{
  int len;
  struct s_iface *iface;
  struct list_head *iface_head = &ifaces.list;
  struct ifinfomsg *ifinfo = NLMSG_DATA(iface_msg->hdr);
  struct rtattr *rta;  

  if ((iface = ptr_index_get(&ifaces.index, ifinfo->ifi_index)) == NULL) {
    /* sorted insert */
    list_for_each_entry(iface, &ifaces.list, head) {
      if (iface->ifi > ifinfo->ifi_index) {
        iface_head = &iface->head;
        break;
      }
  	}
    
    DBG(&dbg_net, "adding interface %d", ifinfo->ifi_index);
  	if ((iface = malloc(sizeof(struct s_iface))) == NULL) {
  		APPLOG_NOMEM();
  		return FAILURE;
  	}
    list_add_tail(&iface->head, iface_head);
    iface->ifi = ifinfo->ifi_index;
    iface->send_enabled = FALSE;
    ptr_index_set(&ifaces.index, iface->ifi, iface); /* update index */
  }
#ifdef DEBUG
  else {
    DBG(&dbg_net, "updating interface %d", ifinfo->ifi_index);
  }
#endif

  
  len = NLMSG_PAYLOAD(iface_msg->hdr, sizeof(struct ifinfomsg));
  for (rta = IFLA_RTA(ifinfo); RTA_OK(rta, len); rta = RTA_NEXT(rta, len))
  {
    switch(rta->rta_type)
  	{
    	case IFLA_IFNAME:
        strncpy(iface->name, RTA_DATA(rta), IF_NAMESIZE+1);
        DBG(&dbg_net,"interface %d: name %s added", iface->ifi, iface->name);
    	  break;
    	case IFLA_MTU:
        memcpy(&iface->mtu, RTA_DATA(rta), sizeof(iface->mtu));
        DBG(&dbg_net,"interface %d: mtu %d added", iface->ifi, iface->mtu);
    	  break;
    	default:
        //DBG(&dbg_net,"interface %d: unknown attribute %d", iface->ifi, rta->rta_type);
    	  break;
  	}
  }  
  
  return SUCCESS;
}

static int linux_handle_addr(struct nl_msg *addr_msg)
{
  int len;
  int found = FALSE;
  struct s_ip6addr *ip6addr;
  struct list_head *ip6addr_head = &ip6addrs.list;
  struct ifaddrmsg *addr_info = NLMSG_DATA(addr_msg->hdr);
  struct rtattr *rta;
  void *prefix_ptr = NULL;
  void *addr_ptr = NULL;
  
  len = NLMSG_PAYLOAD(addr_msg->hdr, sizeof(struct ifaddrmsg));
  for (rta = IFA_RTA(addr_info); RTA_OK(rta, len); rta = RTA_NEXT(rta, len))
  {
    switch(rta->rta_type)
  	{
    	case IFA_ADDRESS:
        prefix_ptr = RTA_DATA(rta);
    	  break;
      case IFA_LOCAL:
        addr_ptr = RTA_DATA(rta);
        break;
    	default:
        DBG(&dbg_net,"unknown attribute %d", rta->rta_type);
    	  break;
  	}
  }  

  list_for_each_entry(ip6addr, &ip6addrs.list, head) {
		if (ip6addr->iface->ifi == addr_info->ifa_index) {
      if (addr_ptr != NULL && memcmp(&ip6addr->addr, addr_ptr, sizeof(ip6addr->addr)) == 0) {
        found++;
        DBG(&dbg_net, "updating address of interface %d", addr_info->ifa_index);
        break;
      }
		}
    /* sorted insert */
    if (ip6addr->iface->ifi > addr_info->ifa_index) {
      ip6addr_head = &ip6addr->head;
      break;
    }
	}
  
  if (!found) {
  	// Create a record of this request
    DBG(&dbg_net, "adding address of interface %d", addr_info->ifa_index);
  	if ((ip6addr = malloc(sizeof(struct s_ip6addr))) == NULL) {
  		APPLOG_NOMEM();
  		return FAILURE;
  	}
    if (prefix_ptr != NULL) {
      memcpy(&ip6addr->prefix, prefix_ptr, sizeof(ip6addr->prefix));
      if (addr_ptr != NULL)  {
        memcpy(&ip6addr->addr, addr_ptr, sizeof(ip6addr->addr));
      } else {
        memcpy(&ip6addr->addr, prefix_ptr, sizeof(ip6addr->addr));
      }
      inet_ntop(AF_INET6, &ip6addr->addr, (char *)&ip6addr->saddr, sizeof(ip6addr->saddr));
      if (!IN6_IS_ADDR_LOOPBACK(&ip6addr->addr) && addr_info->ifa_prefixlen == 64) {
        ip6addr->cga_params = snd_is_lcl_cga(&ip6addr->addr, addr_info->ifa_index);
       } else {
        ip6addr->cga_params = NULL;
      }
      DBG(&dbg_net,"address: %s/%d %s", ip6addr->saddr, addr_info->ifa_prefixlen, (ip6addr->cga_params) ? "(cga)" : "");
    } else {
      ip6addr->cga_params = NULL;
    }
    ip6addr->prefix_len = addr_info->ifa_prefixlen;
    //ip6addr->scope = addr_info->ifa_scope;
    ip6addr->iface = ptr_index_get(&ifaces.index, addr_info->ifa_index);
    list_add_tail(&ip6addr->head, ip6addr_head);
    htbl_add(ip6addrs.table, ip6addr, &ip6addr->hit); /* update hash table */
  }

  ip6addr->flags = addr_info->ifa_flags; /* update flags only */ 
  if(ip6addr->flags && IFA_F_TENTATIVE) {
    DBG(&dbg_net, "DAD working, address still tentative");
  } else if(ip6addr->flags && IFA_F_PERMANENT) {
    DBG(&dbg_net, "DAD completed, address is unique");
  } else if(ip6addr->flags && IFA_F_DADFAILED) {
    DBG(&dbg_net, "DAD completed, duplicated address detected");
  } else {
    DBG(&dbg_net, "DAD disabled?");
  }

  return SUCCESS;  
}

int linux_get_ifaces()
{
  int r = FAILURE;
  int done = FALSE;
  struct nl_gen_req req;
  struct nl_msg req_msg, answer;

  nl_msg_assign(&req_msg, &req, sizeof(struct nl_gen_req));
  if (nl_msg_init(&answer) != SUCCESS)
    return FAILURE;
  
  memset(&req, 0, sizeof(req));
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtgenmsg));
  req.hdr.nlmsg_type = RTM_GETLINK;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT; 
  
  req.gen.rtgen_family = AF_PACKET;
  
  if (nl_talk(&req_msg, 0, &answer, 0) != SUCCESS) {
    DBG(&dbg_net,"nl_talk() failed");
    return FAILURE;
  }
  
  while(!done) {
    if (answer.msg_len)
    {
  	  for (; NLMSG_OK(answer.hdr, answer.msg_len); answer.hdr = NLMSG_NEXT(answer.hdr, answer.msg_len))
  	  {
  	      switch(answer.hdr->nlmsg_type)
      		{
        		case NLMSG_DONE:
        		  r = SUCCESS;
        		  done++;
              break;
        		case RTM_NEWLINK:
              linux_handle_iface(&answer);
        		  break;
        		default:
              DBG(&dbg_net,"received unexpected message type %d", answer.hdr->nlmsg_type);
              nl_handle_type(&answer);
        		  break;
      		}
      }
      if(!done && nl_recv(&answer, 0) != SUCCESS) {
        DBG(&dbg_net,"nl_recv() failed");
        done++;
        break;
      }
    }
    else
    {
      DBG(&dbg_net,"msg_len = %d", answer.msg_len);
      done++;
    }
  }

  return r;  
}

int linux_get_addrs()
{
  int r = FAILURE;
  int done = FALSE;
  struct nl_ifaddr_req req;
  struct nl_msg req_msg, answer;

  nl_msg_assign(&req_msg, &req, sizeof(struct nl_ifaddr_req));
  if (nl_msg_init(&answer) != SUCCESS)
    return FAILURE;
  
  memset(&req, 0, sizeof(req));
  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.hdr.nlmsg_type = RTM_GETADDR;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_ROOT; 
  
  req.ifa.ifa_family = AF_INET6;
  
  if (nl_talk(&req_msg, 0, &answer, 0) != SUCCESS) {
    DBG(&dbg_net,"nl_talk() failed");
    return FAILURE;
  }
  
  while(!done) {
    if (answer.msg_len)
    {
  	  for (; NLMSG_OK(answer.hdr, answer.msg_len); answer.hdr = NLMSG_NEXT(answer.hdr, answer.msg_len))
  	  {
  	      switch(answer.hdr->nlmsg_type)
      		{
        		case NLMSG_DONE:
        		  r = SUCCESS;
        		  done++;
              break;
        		case RTM_NEWADDR:
              linux_handle_addr(&answer);
        		  break;
        		default:
              DBG(&dbg_net,"received unexpected message type %d", answer.hdr->nlmsg_type);
              nl_handle_type(&answer);
        		  break;
      		}
      }
      if(!done && nl_recv(&answer, 0) != SUCCESS) {
        DBG(&dbg_net,"nl_recv() failed");
        done++;
        break;
      }
    }
    else
    {
      DBG(&dbg_net,"msg_len = %d", answer.msg_len);
      done++;
    }
  }

  return r;    
}

int linux_add_addr(struct in6_addr *a, int ifi, int plen, uint32_t vlife, uint32_t plife)
{
  struct nl_ifaddr_req req;
  struct ifaddrmsg *ifa_ptr;
  struct nl_msg request, answer;
  struct ifa_cacheinfo cinfo;
  int dad_complete = FALSE;

  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.hdr.nlmsg_type = RTM_NEWADDR;
  req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_REPLACE;
  req.ifa.ifa_index = ifi;
  req.ifa.ifa_family = AF_INET6;
  req.ifa.ifa_prefixlen = plen;
  /* This creates the aliased interface */
  /*nl_add_rta(&req.hdr, sizeof(struct nl_ifaddr_req), IFA_LABEL,
      ap->iface->name, strlen(ap->iface->name) + 1);*/
  nl_add_rta(&req.hdr, sizeof(struct nl_ifaddr_req), IFA_LOCAL,
      a, sizeof(struct in6_addr));

  memset(&cinfo, 0, sizeof(cinfo));
  cinfo.ifa_prefered = plife;
  cinfo.ifa_valid = vlife;
  nl_add_rta(&req.hdr, sizeof(struct nl_ifaddr_req), IFA_CACHEINFO, &cinfo, sizeof(cinfo));

  nl_msg_assign(&request, &req, sizeof(struct nl_ifaddr_req));
  if (nl_send(&request, 0) != SUCCESS) {
    DBG(&dbg_net,"nl_send() failed");
    return FAILURE;
  }

  return SUCCESS;
}

int linux_del_addr(struct in6_addr *a, int ifi, int plen)
{
  struct nl_ifaddr_req req;
  struct nl_msg req_msg;
  struct s_ip6addr *addr;

  req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
  req.hdr.nlmsg_type = RTM_DELADDR;
  req.hdr.nlmsg_flags = NLM_F_REQUEST;
  req.ifa.ifa_index = ifi;
  req.ifa.ifa_family = AF_INET6;
  req.ifa.ifa_prefixlen = plen;
  /* This creates the aliased interface */
  /*nl_add_rta(&nlm->hdr, sizeof(*nlm), IFA_LABEL,
      ap->iface->name, strlen(ap->iface->name) + 1);*/
  nl_add_rta(&req.hdr, sizeof(struct nl_ifaddr_req), IFA_LOCAL, a, sizeof(struct in6_addr));

  nl_msg_assign(&req_msg, &req, sizeof(struct nl_ifaddr_req));
  if (nl_send(&req_msg, 0) != SUCCESS)
    return FAILURE;

  if ((addr = find_ip6addr(a, ifi)) != NULL)
    list_del(&addr->head);
  
  return SUCCESS;
}

int net_handle_msg(struct nl_msg *msg)
{
  switch(msg->hdr->nlmsg_type)
  {
        case RTM_NEWLINK:
      	  DBG(&dbg_net, "message type RTM_NEWLINK received");
          linux_handle_iface(msg);
      	  break;
        case RTM_DELLINK:
          DBG(&dbg_net, "message type RTM_DELLINK received");
          break;
        case RTM_GETLINK:
          DBG(&dbg_net, "message type RTM_GETLINK received");
          break;
        case RTM_NEWADDR:
          DBG(&dbg_net, "message type RTM_NEWADDR received");
          linux_handle_addr(msg);
          break;
        case RTM_DELADDR:
          DBG(&dbg_net, "message type RTM_DELADDR received");
          break;
        case RTM_GETADDR:
          DBG(&dbg_net, "message type RTM_GETADDR received");
          break;
        default:
          DBG(&dbg_net, "unsupported RTM message type %d received", msg->hdr->nlmsg_type);
          break;
  }
  
  return SUCCESS;
}