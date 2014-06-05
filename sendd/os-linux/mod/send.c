/*  
 *  send.c - Module for Netfilter for diverting ND traffic from kernel to SEND daemon in userspace.
 *  Author: Lukas Bezdicek 
 */
#include <linux/module.h>	/* Needed by all modules */
#include <linux/kernel.h>	/* Needed for KERN_INFO */
#include <linux/init.h>		/* Needed for macros */
#include <linux/ipv6.h>
#include <net/ipv6.h>
#include <net/ndisc.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>

#include "../../../include/config.h"

#define MOD_AUTHOR "Lukas Bezdicek"
#define MOD_DESC "Module for Netfilter for diverting ND traffic from kernel to SEND daemon in userspace"

static unsigned int nd_hook(const struct nf_hook_ops *ops, 
                            struct sk_buff *skb, 
                            const struct net_device *in, 
                            const struct net_device *out, 
                            int (*okfn)(struct sk_buff *));

static struct nf_hook_ops nd_hook_in_ops __read_mostly = {
  .hook = nd_hook,
  //.priv = ,
  //.owner = ,
  .pf = NFPROTO_IPV6,
  .hooknum = NF_INET_LOCAL_IN,
  .priority = NF_IP6_PRI_SECURITY,
};

static struct nf_hook_ops nd_hook_out_ops __read_mostly = {
  .hook = nd_hook,
  //.priv = ,
  //.owner = ,
  .pf = NFPROTO_IPV6,
  .hooknum = NF_INET_LOCAL_OUT,
  .priority = NF_IP6_PRI_SECURITY,
};

static unsigned int nd_hook(const struct nf_hook_ops *ops, 
                            struct sk_buff *skb, 
                            const struct net_device *in, 
                            const struct net_device *out, 
                            int (*okfn)(struct sk_buff *))
{
  struct ipv6hdr *ip6_header = ipv6_hdr(skb);
  struct icmp6hdr *icmp6_header;
  
  if(ip6_header->nexthdr == NEXTHDR_ICMP)
  {
    icmp6_header = icmp6_hdr(skb);
    switch(icmp6_header->icmp6_type)
    {
      case NDISC_ROUTER_SOLICITATION:
      case NDISC_ROUTER_ADVERTISEMENT:
      case NDISC_NEIGHBOUR_SOLICITATION:
      case NDISC_NEIGHBOUR_ADVERTISEMENT:
      case NDISC_REDIRECT:
        //printk(KERN_INFO "%s%s, ND packet.\n", in ? "Hello" : "", out ? "Farewell" : "");
        return NF_QUEUE_NR(SND_NFQ_NUM);
      default:
        return NF_ACCEPT;
    }
  } else {
    return NF_ACCEPT;
  }
}

static int __init send_module_init(void)
{
  int res;

  res = nf_register_hook(&nd_hook_in_ops);
  if(res != 0) 
    return res;

  res = nf_register_hook(&nd_hook_out_ops);
  if(res != 0)
    nf_unregister_hook(&nd_hook_in_ops);

  return res;
}

static void __exit send_module_cleanup(void)
{
  nf_unregister_hook(&nd_hook_in_ops);
  nf_unregister_hook(&nd_hook_out_ops);
}

module_init(send_module_init);
module_exit(send_module_cleanup);

MODULE_LICENSE("GPL");
MODULE_AUTHOR(MOD_AUTHOR);
MODULE_DESCRIPTION(MOD_DESC);
