/**
 * @file
 * @brief
 *
 * @date 19.06.11
 * @author Anton Bondarev
 * @author Ilia Vaprol
 */

#include <assert.h>
#include <errno.h>
#include <arpa/inet.h>
#include <net/l0/net_crypt.h>
#include <net/l0/net_tx.h>
#include <net/neighbour.h>
#include <net/netdevice.h>
#include <net/skbuff.h>
#include <stddef.h>
#include <util/array.h>
#include <net/socket/packet.h>
#include <net/l2/ethernet.h>
#include <util/log.h>

#define LOG_LEVEL OPTION_GET(NUMBER, log_level)

static int nt_build_hdr(struct sk_buff *skb,
		struct net_header_info *hdr_info,
		struct net_device *dev) {
	int ret;
	unsigned char dst_haddr[MAX_ADDR_LEN];

	assert(skb != NULL);
	assert(dev != NULL);

	if (hdr_info == NULL) {
		return 0; /* ok: already built */
	}

	/* resolve hw address */
	if (hdr_info->src_hw == NULL) {
		hdr_info->src_hw = &dev->dev_addr[0];
	}
	if (hdr_info->dst_hw == NULL) {
		if (hdr_info->dst_p != NULL) {
			ret = neighbour_get_haddr(hdr_info->type,
					hdr_info->dst_p, dev, dev->type,
					ARRAY_SIZE(dst_haddr), &dst_haddr[0]);
			if (ret == 0) {
				hdr_info->dst_hw = &dst_haddr[0];
			} else if (ret == -ENOENT && (dev->flags & IFF_NOARP)) {
				hdr_info->dst_hw = NULL;
			} else {
				return ret;
			}
		} else {
			hdr_info->dst_hw = &dev->broadcast[0];
		}
	}

	/* try to build */
	assert(dev->ops != NULL);
	assert(dev->ops->build_hdr != NULL);
	return dev->ops->build_hdr(skb, hdr_info);
}

int net_tx(struct sk_buff *skb,
		struct net_header_info *hdr_info) {
	int ret;
	size_t skb_len;
	struct net_device *dev;

	assert(skb != NULL);

	dev = skb->dev;
	assert(dev != NULL);

	if (!(dev->flags & IFF_UP)) {
		log_error("device is down");
		skb_free(skb);
		return -ENETDOWN;
	}

	if (0 != nt_build_hdr(skb, hdr_info, dev)) {
		assert(hdr_info != NULL);
		ret = neighbour_send_after_resolve(hdr_info->type,
				hdr_info->dst_p, hdr_info->p_len,
				dev, skb);
		if (ret != 0)
			log_debug("neighbour_send_after_resolve = %d", ret);

		return ret;
	}

	skb_len = skb->len;

	log_debug("%p len %zu type %#.6hx", skb, skb->len, ntohs(skb->mac.ethh->h_proto));

	/*
	 * http://www.linuxfoundation.org/collaborate/workgroups/networking/kernel_flow#Transmission_path
	 * Search for:
	 * dev_hard_start_xmit() calls the hard_start_xmit virtual method for the net_device.
	 * But first, it calls dev_queue_xmit_nit(), which checks if a packet handler has been registered
	 * for the ETH_P_ALL protocol. This is used for tcpdump.
	 */
	sock_packet_add(skb, htons(ETH_P_ALL));

	skb = net_encrypt(skb);
	if (skb == NULL) {
		return 0;
	}

	assert(dev->drv_ops != NULL);
	assert(dev->drv_ops->xmit != NULL);
	ret = dev->drv_ops->xmit(dev, skb);
	if (ret != 0) {
		log_debug("xmit = %d", ret);
		skb_free(skb);
		dev->stats.tx_err++;
		return ret;
	}

	dev->stats.tx_packets++;
	dev->stats.tx_bytes += skb_len;

	return 0;
}
