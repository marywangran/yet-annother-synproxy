/*
 * Copyright (c) 2013 Patrick McHardy <kaber@trash.net>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */
// sysctl -w net.ipv4.tcp_syncookies=2
// sysctl -w net.netfilter.nf_conntrack_tcp_loose=0
// iptables -t raw -I PREROUTING -i eth4 -p tcp -m tcp --syn --dport 80 -j CT --notrack
// iptables -A INPUT -i eth4 -p tcp --dport 80 -m state --state UNTRACKED,INVALID 	-j SYNPROXY --sack-perm --timestamp --wscale 7 --mss 1460
// iptables -A INPUT -i eth4 -p tcp --dport 80 -m state --state INVALID 	-j DROP
#include <linux/module.h>
#include <linux/skbuff.h>
#include <net/tcp.h>

#include <linux/netfilter_ipv4/ip_tables.h>
#include <linux/netfilter/x_tables.h>
#include <linux/netfilter/xt_SYNPROXY.h>
#include <net/netfilter/nf_conntrack.h>
#include <net/netfilter/nf_conntrack_ecache.h>
#include <net/netfilter/nf_conntrack_seqadj.h>
#include <net/netfilter/nf_conntrack_synproxy.h>

static struct iphdr *
synproxy_build_ip(struct net *net, struct sk_buff *skb, __be32 saddr,
		  __be32 daddr)
{
	struct iphdr *iph;

	skb_reset_network_header(skb);
	iph = (struct iphdr *)skb_put(skb, sizeof(*iph));
	iph->version	= 4;
	iph->ihl	= sizeof(*iph) / 4;
	iph->tos	= 0;
	iph->id		= 0;
	iph->frag_off	= htons(IP_DF);
	iph->ttl	= net->ipv4.sysctl_ip_default_ttl;
	iph->protocol	= IPPROTO_TCP;
	iph->check	= 0;
	iph->saddr	= saddr;
	iph->daddr	= daddr;

	return iph;
}

static void
synproxy_send_tcp(struct net *net,
		  const struct sk_buff *skb, struct sk_buff *nskb,
		  struct nf_conntrack *nfct, enum ip_conntrack_info ctinfo,
		  struct iphdr *niph, struct tcphdr *nth,
		  unsigned int tcp_hdr_size)
{
	nth->check = ~tcp_v4_check(tcp_hdr_size, niph->saddr, niph->daddr, 0);
	nskb->ip_summed   = CHECKSUM_PARTIAL;
	nskb->csum_start  = (unsigned char *)nth - nskb->head;
	nskb->csum_offset = offsetof(struct tcphdr, check);

	skb_dst_set_noref(nskb, skb_dst(skb));
	nskb->protocol = htons(ETH_P_IP);
	if (ip_route_me_harder(net, nskb, RTN_UNSPEC))
		goto free_nskb;

	if (nfct) {
		nskb->nfct = nfct;
		nskb->nfctinfo = ctinfo;
		nf_conntrack_get(nfct);
	}

	ip_local_out(net, nskb->sk, nskb);
	return;

free_nskb:
	kfree_skb(nskb);
}

static void
synproxy_send_client_synack(struct net *net,
			    const struct sk_buff *skb, const struct tcphdr *th,
			    const struct synproxy_options *opts)
{
	struct sk_buff *nskb;
	struct iphdr *iph, *niph;
	struct tcphdr *nth;
	unsigned int tcp_hdr_size;
	u16 mss = opts->mss;

	iph = ip_hdr(skb);

	tcp_hdr_size = sizeof(*nth) + synproxy_options_size(opts);
	nskb = alloc_skb(sizeof(*niph) + tcp_hdr_size + MAX_TCP_HEADER,
			 GFP_ATOMIC);
	if (nskb == NULL)
		return;
	skb_reserve(nskb, MAX_TCP_HEADER);

	niph = synproxy_build_ip(net, nskb, iph->daddr, iph->saddr);

	skb_reset_transport_header(nskb);
	nth = (struct tcphdr *)skb_put(nskb, tcp_hdr_size);
	nth->source	= th->dest;
	nth->dest	= th->source;
	nth->seq	= htonl(__cookie_v4_init_sequence(iph, th, &mss));
	nth->ack_seq	= htonl(ntohl(th->seq) + 1);
	tcp_flag_word(nth) = TCP_FLAG_SYN | TCP_FLAG_ACK;
	if (opts->options & XT_SYNPROXY_OPT_ECN)
		tcp_flag_word(nth) |= TCP_FLAG_ECE;
	nth->doff	= tcp_hdr_size / 4;
	nth->window	= htons(29200);
	nth->check	= 0;
	nth->urg_ptr	= 0;

	synproxy_build_options(nth, opts);

	synproxy_send_tcp(net, skb, nskb, skb->nfct, IP_CT_ESTABLISHED_REPLY,
			  niph, nth, tcp_hdr_size);
}

int dummy_return(struct sk_buff *skb)
{
	return 0;
}

static unsigned int
synproxy_tg4(struct sk_buff *skb, const struct xt_action_param *par)
{
	const struct xt_synproxy_info *info = par->targinfo;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct net *net = par->net;
	struct ip_ct_tcp *state;
	struct synproxy_net *snet = synproxy_pernet(net);
	struct synproxy_options opts = {};
	struct tcphdr *th, _th;

	if (nf_ip_checksum(skb, par->hooknum, par->thoff, IPPROTO_TCP))
		return NF_DROP;

	th = skb_header_pointer(skb, par->thoff, sizeof(_th), &_th);
	if (th == NULL)
		return NF_DROP;

	if (!synproxy_parse_options(skb, par->thoff, th, &opts))
		return NF_DROP;

	if (th->syn && !(th->ack || th->fin || th->rst)) {
	
		this_cpu_inc(snet->stats->syn_received);

		if (th->ece && th->cwr)
			opts.options |= XT_SYNPROXY_OPT_ECN;

		opts.options &= info->options;
		if (opts.options & XT_SYNPROXY_OPT_TIMESTAMP)
			synproxy_init_timestamp_cookie(info, &opts);
		else
			opts.options &= ~(XT_SYNPROXY_OPT_WSCALE |
					  XT_SYNPROXY_OPT_SACK_PERM |
					  XT_SYNPROXY_OPT_ECN);
		
		synproxy_send_client_synack(net, skb, th, &opts);
		return NF_DROP;
	
	} else if (th->ack && !(th->fin || th->rst || th->syn)) {
		int mss;
		bool tse;
		struct tcp_options_received tcp_opt;
		memset(&tcp_opt, 0, sizeof(tcp_opt));
		mss = __cookie_v4_check(ip_hdr(skb), th, ntohl(th->ack_seq) - 1);
		tcp_parse_options(skb, &tcp_opt, 0, NULL);
		tse = cookie_timestamp_decode(&tcp_opt);
		
		if (mss && tse) {
			tcp_flag_word(th) |= TCP_FLAG_SYN;
			tcp_flag_word(th) &= ~TCP_FLAG_ACK;
			skb->nfct = NULL;
			NF_HOOK_THRESH(NFPROTO_IPV4, NF_INET_PRE_ROUTING, net, NULL, skb, skb->dev, NULL, dummy_return, NF_IP_PRI_CONNTRACK);
			return XT_CONTINUE;
		}
		return NF_DROP;
	}

	return XT_CONTINUE;
}

static inline __u32 synproxy_segment_seq_plus_len(__u32 seq,
					 size_t len,
					 unsigned int dataoff,
					 const struct tcphdr *tcph)
{
	return (seq + len - dataoff - tcph->doff*4
		+ (tcph->syn ? 1 : 0) + (tcph->fin ? 1 : 0));
}

static unsigned int ipv4_synproxy_hook(void *priv,
				       struct sk_buff *skb,
				       const struct nf_hook_state *nhs)
{
	struct net *net = nhs->net;
	enum ip_conntrack_info ctinfo;
	struct nf_conn *ct;
	struct ip_ct_tcp *state;
	const struct iphdr *iph = ip_hdr(skb);
	struct tcphdr *th, _th;
	unsigned int thoff;
	
	ct = nf_ct_get(skb, &ctinfo);
	if (ct && !nf_ct_is_untracked(ct) && iph->protocol == IPPROTO_TCP) {
		thoff = ip_hdrlen(skb);
		th = skb_header_pointer(skb, thoff, sizeof(_th), &_th);
		if (th &&
			(th->syn && !(th->ack || th->fin || th->rst))) {
			unsigned int dataoff;
			state = &ct->proto.tcp;
			
			NF_HOOK_THRESH(NFPROTO_IPV4, NF_INET_LOCAL_IN, net, NULL, skb, skb->dev, NULL, dummy_return, NF_IP_PRI_CONNTRACK_CONFIRM);

			tcp_flag_word(th) &= ~TCP_FLAG_SYN;
			tcp_flag_word(th) |= TCP_FLAG_ACK;

			dataoff = skb_network_offset(skb) + (iph->ihl << 2);
			ct = nf_ct_get(skb, &ctinfo);
			state = &ct->proto.tcp;
			
			state = &ct->proto.tcp;
			state->state = TCP_CONNTRACK_ESTABLISHED;
			
			state->last_dir = IP_CT_DIR_ORIGINAL;
#define TCP_ACK_SET	3
			state->last_index = TCP_ACK_SET;
			state->last_seq = ntohl(th->seq);
			state->last_ack = ntohl(th->ack_seq);;
			state->last_end = synproxy_segment_seq_plus_len(ntohl(th->seq), skb->len, dataoff, th);
			state->last_win = ntohs(th->window);
			state->retrans = 0;
			// .... TODO Adjust
			
			if (!test_and_set_bit(IPS_SEEN_REPLY_BIT, &ct->status)) {
				nf_conntrack_event_cache(IPCT_REPLY, ct);
			}

			return NF_STOP;
		}

	}
	return NF_ACCEPT;

}

static int synproxy_tg4_check(const struct xt_tgchk_param *par)
{
	const struct ipt_entry *e = par->entryinfo;

	if (e->ip.proto != IPPROTO_TCP ||
	    e->ip.invflags & XT_INV_PROTO)
		return -EINVAL;

	return nf_ct_l3proto_try_module_get(par->family);
}

static void synproxy_tg4_destroy(const struct xt_tgdtor_param *par)
{
	nf_ct_l3proto_module_put(par->family);
}

static struct xt_target synproxy_tg4_reg __read_mostly = {
	.name		= "SYNPROXY",
	.family		= NFPROTO_IPV4,
	.hooks		= (1 << NF_INET_LOCAL_IN) | (1 << NF_INET_FORWARD),
	.target		= synproxy_tg4,
	.targetsize	= sizeof(struct xt_synproxy_info),
	.checkentry	= synproxy_tg4_check,
	.destroy	= synproxy_tg4_destroy,
	.me		= THIS_MODULE,
};

static struct nf_hook_ops ipv4_synproxy_ops[] __read_mostly = {
	{
		.hook		= ipv4_synproxy_hook,
		.pf		= NFPROTO_IPV4,
		.hooknum	= NF_INET_PRE_ROUTING,
		.priority	= NF_IP_PRI_CONNTRACK + 1,
	},
};

static int __init synproxy_tg4_init(void)
{
	int err;

	err = nf_register_hooks(ipv4_synproxy_ops,
				ARRAY_SIZE(ipv4_synproxy_ops));
	if (err < 0)
		goto err1;

	err = xt_register_target(&synproxy_tg4_reg);
	if (err < 0)
		goto err2;

	return 0;

err2:
	nf_unregister_hooks(ipv4_synproxy_ops, ARRAY_SIZE(ipv4_synproxy_ops));
err1:
	return err;
}

static void __exit synproxy_tg4_exit(void)
{
	xt_unregister_target(&synproxy_tg4_reg);
	nf_unregister_hooks(ipv4_synproxy_ops, ARRAY_SIZE(ipv4_synproxy_ops));
}

module_init(synproxy_tg4_init);
module_exit(synproxy_tg4_exit);

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Patrick McHardy <kaber@trash.net>");
