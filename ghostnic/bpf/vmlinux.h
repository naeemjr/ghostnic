/* SPDX-License-Identifier: GPL-2.0 */
/*
 * Minimal vmlinux-style header for GhostNIC.
 *
 * On kernels that expose /sys/kernel/btf/vmlinux this file can be regenerated
 * with `make vmlinux`.  For portability across build environments it pulls the
 * stable networking types directly from the Linux UAPI headers.
 */
#ifndef __VMLINUX_H__
#define __VMLINUX_H__

#include <linux/types.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/in.h>
#include <linux/pkt_cls.h>
#include <asm/byteorder.h>

#ifndef __packed
#define __packed __attribute__((packed))
#endif

#endif /* __VMLINUX_H__ */
