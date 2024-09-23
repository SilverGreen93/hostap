/*
 * Wired Ethernet driver interface
 * Copyright (c) 2005-2009, Jouni Malinen <j@w1.fi>
 * Copyright (c) 2004, Gunter Burchardt <tira@isx.de>
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "includes.h"

#include "common.h"
#include "eloop.h"
#include "driver.h"
#include "driver_wired_common.h"

#ifdef CONFIG_ENABLE_MAB
#include <pthread.h>
#include <linux/nl80211.h>
#include <netlink/netlink.h>
#include <netlink/msg.h>
#include <netlink/socket.h>
#include "mab/mab.h"
#endif /* CONFIG_ENABLE_MAB */

#include <sys/ioctl.h>
#ifdef __linux__
#include <netpacket/packet.h>
#include <net/if_arp.h>
#endif /* __linux__ */
#if defined(__FreeBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__)
#include <net/if_dl.h>
#include <net/if_media.h>
#endif /* defined(__FreeBSD__) || defined(__DragonFly__) || defined(__FreeBSD_kernel__) */
#ifdef __sun__
#include <sys/sockio.h>
#endif /* __sun__ */

#ifdef _MSC_VER
#pragma pack(push, 1)
#endif /* _MSC_VER */

struct ieee8023_hdr {
	u8 dest[6];
	u8 src[6];
	u16 ethertype;
} STRUCT_PACKED;

#ifdef _MSC_VER
#pragma pack(pop)
#endif /* _MSC_VER */

#ifndef IFLA_BRPORT_ISOLATED
#define IFLA_BRPORT_ISOLATED	33
#endif

struct wpa_driver_wired_data {
	struct driver_wired_common_data common;

	int dhcp_sock; /* socket for dhcp packets */
	int use_pae_group_addr;
};


/* TODO: detecting new devices should eventually be changed from using DHCP
 * snooping to trigger on any packet from a new layer 2 MAC address, e.g.,
 * based on ebtables, etc. */

struct dhcp_message {
	u_int8_t op;
	u_int8_t htype;
	u_int8_t hlen;
	u_int8_t hops;
	u_int32_t xid;
	u_int16_t secs;
	u_int16_t flags;
	u_int32_t ciaddr;
	u_int32_t yiaddr;
	u_int32_t siaddr;
	u_int32_t giaddr;
	u_int8_t chaddr[16];
	u_int8_t sname[64];
	u_int8_t file[128];
	u_int32_t cookie;
	u_int8_t options[308]; /* 312 - cookie */
};


#ifdef __linux__
static void handle_data(void *ctx, unsigned char *buf, size_t len)
{
#ifdef HOSTAPD
	struct ieee8023_hdr *hdr;
	u8 *pos, *sa;
	size_t left;
	union wpa_event_data event;

	/* must contain at least ieee8023_hdr 6 byte source, 6 byte dest,
	 * 2 byte ethertype */
	if (len < 14) {
		wpa_printf(MSG_MSGDUMP, "handle_data: too short (%lu)",
			   (unsigned long) len);
		return;
	}

	hdr = (struct ieee8023_hdr *) buf;

	switch (ntohs(hdr->ethertype)) {
	case ETH_P_PAE: //ETH_P_IP:
		wpa_printf(MSG_MSGDUMP, "Received EAPOL packet");
		sa = hdr->src;
		os_memset(&event, 0, sizeof(event));
		event.new_sta.addr = sa;
		wpa_supplicant_event(ctx, EVENT_NEW_STA, &event);

		pos = (u8 *) (hdr + 1);
		left = len - sizeof(*hdr);
		drv_event_eapol_rx(ctx, sa, pos, left);
		break;

	default:
		wpa_printf(MSG_DEBUG, "Unknown ethertype 0x%04x in data frame",
			   ntohs(hdr->ethertype));
		break;
	}
#endif /* HOSTAPD */
}


static void handle_read(int sock, void *eloop_ctx, void *sock_ctx)
{
	int len;
	unsigned char buf[3000];

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		wpa_printf(MSG_ERROR, "recv: %s", strerror(errno));
		return;
	}

	handle_data(eloop_ctx, buf, len);
}


static void handle_dhcp(int sock, void *eloop_ctx, void *sock_ctx)
{
	int len;
	unsigned char buf[3000];
	struct dhcp_message *msg;
	u8 *mac_address;
	union wpa_event_data event;

	len = recv(sock, buf, sizeof(buf), 0);
	if (len < 0) {
		wpa_printf(MSG_ERROR, "recv: %s", strerror(errno));
		return;
	}

	/* must contain at least dhcp_message->chaddr */
	if (len < 44) {
		wpa_printf(MSG_MSGDUMP, "handle_dhcp: too short (%d)", len);
		return;
	}

	msg = (struct dhcp_message *) buf;
	mac_address = (u8 *) &(msg->chaddr);

	wpa_printf(MSG_MSGDUMP, "Got DHCP broadcast packet from " MACSTR,
		   MAC2STR(mac_address));

	os_memset(&event, 0, sizeof(event));
	event.new_sta.addr = mac_address;
	wpa_supplicant_event(eloop_ctx, EVENT_NEW_STA, &event);
}
#endif /* __linux__ */


static int wired_init_sockets(struct wpa_driver_wired_data *drv, u8 *own_addr)
{
#ifdef __linux__
	struct ifreq ifr;
	struct sockaddr_ll addr;
	struct sockaddr_in addr2;
	int n = 1;

	drv->common.sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_PAE)); // numai frame eapol
	if (drv->common.sock < 0) {
		wpa_printf(MSG_ERROR, "socket[PF_PACKET,SOCK_RAW]: %s",
			   strerror(errno));
		return -1;
	}

	if (eloop_register_read_sock(drv->common.sock, handle_read,
				     drv->common.ctx, NULL)) {
		wpa_printf(MSG_INFO, "Could not register read socket");
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, drv->common.ifname, sizeof(ifr.ifr_name));
	if (ioctl(drv->common.sock, SIOCGIFINDEX, &ifr) != 0) {
		wpa_printf(MSG_ERROR, "ioctl(SIOCGIFINDEX): %s",
			   strerror(errno));
		return -1;
	}

	os_memset(&addr, 0, sizeof(addr));
	addr.sll_family = AF_PACKET;
	addr.sll_ifindex = ifr.ifr_ifindex;
	wpa_printf(MSG_DEBUG, "Opening raw packet socket for ifindex %d",
		   addr.sll_ifindex);

	if (bind(drv->common.sock, (struct sockaddr *) &addr, sizeof(addr)) < 0)
	{
		wpa_printf(MSG_ERROR, "bind: %s", strerror(errno));
		return -1;
	}

	/* filter multicast address */
	if (wired_multicast_membership(drv->common.sock, ifr.ifr_ifindex,
				       pae_group_addr, 1) < 0) {
		wpa_printf(MSG_ERROR, "wired: Failed to add multicast group "
			   "membership");
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_name, drv->common.ifname, sizeof(ifr.ifr_name));
	if (ioctl(drv->common.sock, SIOCGIFHWADDR, &ifr) != 0) {
		wpa_printf(MSG_ERROR, "ioctl(SIOCGIFHWADDR): %s",
			   strerror(errno));
		return -1;
	}

	if (ifr.ifr_hwaddr.sa_family != ARPHRD_ETHER) {
		wpa_printf(MSG_INFO, "Invalid HW-addr family 0x%04x",
			   ifr.ifr_hwaddr.sa_family);
		return -1;
	}
	os_memcpy(own_addr, ifr.ifr_hwaddr.sa_data, ETH_ALEN);

	/* setup dhcp listen socket for sta detection */
	if ((drv->dhcp_sock = socket(PF_INET, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		wpa_printf(MSG_ERROR, "socket call failed for dhcp: %s",
			   strerror(errno));
		return -1;
	}

	if (eloop_register_read_sock(drv->dhcp_sock, handle_dhcp,
				     drv->common.ctx, NULL)) {
		wpa_printf(MSG_INFO, "Could not register read socket");
		return -1;
	}

	os_memset(&addr2, 0, sizeof(addr2));
	addr2.sin_family = AF_INET;
	addr2.sin_port = htons(67);
	addr2.sin_addr.s_addr = INADDR_ANY;

	if (setsockopt(drv->dhcp_sock, SOL_SOCKET, SO_REUSEADDR, (char *) &n,
		       sizeof(n)) == -1) {
		wpa_printf(MSG_ERROR, "setsockopt[SOL_SOCKET,SO_REUSEADDR]: %s",
			   strerror(errno));
		return -1;
	}
	if (setsockopt(drv->dhcp_sock, SOL_SOCKET, SO_BROADCAST, (char *) &n,
		       sizeof(n)) == -1) {
		wpa_printf(MSG_ERROR, "setsockopt[SOL_SOCKET,SO_BROADCAST]: %s",
			   strerror(errno));
		return -1;
	}

	os_memset(&ifr, 0, sizeof(ifr));
	os_strlcpy(ifr.ifr_ifrn.ifrn_name, drv->common.ifname, IFNAMSIZ);
	if (setsockopt(drv->dhcp_sock, SOL_SOCKET, SO_BINDTODEVICE,
		       (char *) &ifr, sizeof(ifr)) < 0) {
		wpa_printf(MSG_ERROR,
			   "setsockopt[SOL_SOCKET,SO_BINDTODEVICE]: %s",
			   strerror(errno));
		return -1;
	}

	if (bind(drv->dhcp_sock, (struct sockaddr *) &addr2,
		 sizeof(struct sockaddr)) == -1) {
		wpa_printf(MSG_ERROR, "bind: %s", strerror(errno));
		return -1;
	}

	return 0;
#else /* __linux__ */
	return -1;
#endif /* __linux__ */
}


static int wired_send_eapol(void *priv, const u8 *addr,
			    const u8 *data, size_t data_len, int encrypt,
			    const u8 *own_addr, u32 flags, int link_id)
{
	struct wpa_driver_wired_data *drv = priv;
	struct ieee8023_hdr *hdr;
	size_t len;
	u8 *pos;
	int res;

	len = sizeof(*hdr) + data_len;
	hdr = os_zalloc(len);
	if (hdr == NULL) {
		wpa_printf(MSG_INFO,
			   "malloc() failed for wired_send_eapol(len=%lu)",
			   (unsigned long) len);
		return -1;
	}

	os_memcpy(hdr->dest, drv->use_pae_group_addr ? pae_group_addr : addr,
		  ETH_ALEN);
	os_memcpy(hdr->src, own_addr, ETH_ALEN);
	hdr->ethertype = htons(ETH_P_PAE);

	pos = (u8 *) (hdr + 1);
	os_memcpy(pos, data, data_len);

	res = send(drv->common.sock, (u8 *) hdr, len, 0);
	os_free(hdr);

	if (res < 0) {
		wpa_printf(MSG_ERROR,
			   "wired_send_eapol - packet len: %lu - failed: send: %s",
			   (unsigned long) len, strerror(errno));
	}

	return res;
}


static struct nl_sock * nl_create_handle(struct nl_cb *cb, const char *dbg)
{
	struct nl_sock *handle;

	handle = nl_socket_alloc_cb(cb);
	if (handle == NULL) {
		wpa_printf(MSG_ERROR, "nl80211: Failed to allocate netlink "
			   "callbacks (%s)", dbg);
		return NULL;
	}

	if (genl_connect(handle)) {
		wpa_printf(MSG_ERROR, "nl80211: Failed to connect to generic "
			   "netlink (%s)", dbg);
		nl_socket_free(handle);
		return NULL;
	}

	return handle;
}


static void nl_destroy_handles(struct nl_sock **handle)
{
	if (*handle == NULL)
		return;
	nl_socket_free(*handle);
	*handle = NULL;
}


static void * wired_driver_hapd_init(struct hostapd_data *hapd,
				     struct wpa_init_params *params)
{
	struct wpa_driver_wired_data *drv;
#ifdef CONFIG_ENABLE_MAB
	pthread_t thread;
#endif /* CONFIG_ENABLE_MAB */

	drv = os_zalloc(sizeof(struct wpa_driver_wired_data));
	if (drv == NULL) {
		wpa_printf(MSG_INFO,
			   "Could not allocate memory for wired driver data");
		return NULL;
	}

	drv->common.ctx = hapd;
	os_strlcpy(drv->common.ifname, params->ifname,
		   sizeof(drv->common.ifname));
	drv->use_pae_group_addr = params->use_pae_group_addr;

	drv->common.nl_cb = nl_cb_alloc(NL_CB_DEFAULT);
	if (drv->common.nl_cb == NULL) {
		wpa_printf(MSG_ERROR, "nl80211: Failed to allocate netlink "
			   "callbacks");
		return NULL;
	}

	drv->common.nl = nl_create_handle(drv->common.nl_cb, "nl");
	if (drv->common.nl == NULL)
		goto err;

	drv->common.nl80211_id = genl_ctrl_resolve(drv->common.nl, "nl80211");
	if (drv->common.nl80211_id < 0) {
		wpa_printf(MSG_ERROR, "nl80211: 'nl80211' generic netlink not "
			   "found");
		goto err;
	}

	drv->common.nlctrl_id = genl_ctrl_resolve(drv->common.nl, "nlctrl");
	if (drv->common.nlctrl_id < 0) {
		wpa_printf(MSG_ERROR,
			   "nl80211: 'nlctrl' generic netlink not found");
		goto err;
	}

	drv->common.nl_event = nl_create_handle(drv->common.nl_cb, "event");
	if (drv->common.nl_event == NULL)
		goto err;

	if (wired_init_sockets(drv, params->own_addr)) {
		os_free(drv);
		return NULL;
	}

#ifdef CONFIG_ENABLE_MAB
	if (pthread_create(&thread, NULL, mac_learn_thread, hapd) != 0) {
		perror(">>>>>>>>>>>>>>>>>>>>> MIHAI: Failed to create thread");
		return NULL;
	}
#endif /* CONFIG_ENABLE_MAB */

	return drv;

err:
	nl_destroy_handles(&drv->common.nl_event);
	nl_destroy_handles(&drv->common.nl);
	nl_cb_put(drv->common.nl_cb);
	return NULL;
}


static void wired_driver_hapd_deinit(void *priv)
{
	struct wpa_driver_wired_data *drv = priv;

	if (drv->common.sock >= 0) {
		eloop_unregister_read_sock(drv->common.sock);
		close(drv->common.sock);
	}

	if (drv->dhcp_sock >= 0) {
		eloop_unregister_read_sock(drv->dhcp_sock);
		close(drv->dhcp_sock);
	}

	os_free(drv);
}


static void * wpa_driver_wired_init(void *ctx, const char *ifname)
{
	struct wpa_driver_wired_data *drv;

	drv = os_zalloc(sizeof(*drv));
	if (drv == NULL)
		return NULL;

	if (driver_wired_init_common(&drv->common, ifname, ctx) < 0) {
		os_free(drv);
		return NULL;
	}

	return drv;
}


static void wpa_driver_wired_deinit(void *priv)
{
	struct wpa_driver_wired_data *drv = priv;

	driver_wired_deinit_common(&drv->common);
	os_free(drv);
}


void * wired_cmd(struct wpa_driver_wired_data *drv,
		   struct nl_msg *msg, int flags, uint8_t cmd)
{
	if (TEST_FAIL())
		return NULL;
	return genlmsg_put(msg, 0, 0, drv->common.nl80211_id,
			   0, flags, cmd, 0);
}


static int wired_set_iface_id(struct nl_msg *msg, struct wpa_driver_wired_data *drv)
{
	//if (bss->wdev_id_set)
	//	return nla_put_u64(msg, NL80211_ATTR_WDEV, bss->wdev_id);
	int ifindex = if_nametoindex(drv->common.ifname);
	return nla_put_u32(msg, NL80211_ATTR_IFINDEX, ifindex);
}


struct nl_msg * wired_cmd_msg(struct wpa_driver_wired_data *drv, int flags, uint8_t cmd)
{
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	if (!msg)
		return NULL;

	if (!wired_cmd(drv, msg, flags, cmd) ||
	    wired_set_iface_id(msg, drv) < 0) {
		nlmsg_free(msg);
		return NULL;
	}

	return msg;
}


static int wired_create_iface_once(struct wpa_driver_wired_data *drv,
				     const char *ifname,
				     enum wpa_driver_if_type iftype,
				     const u8 *addr, int wds,
				     int (*handler)(struct nl_msg *, void *),
				     void *arg)
{
	int ifidx;
	//int ret = -ENOBUFS;

	wpa_printf(MSG_DEBUG, "MIHAI: Create interface iftype %d", iftype);
	wpa_printf(MSG_DEBUG, "MIHAI: Create interface ifname %s", ifname);

	// msg = wired_cmd_msg(drv, 0, NL80211_CMD_NEW_INTERFACE);

	// if (!msg ||
	//     nla_put_string(msg, NL80211_ATTR_IFNAME, ifname) ||
	//     nla_put_u32(msg, NL80211_ATTR_IFTYPE, iftype))
	// 	goto fail;

	// if (iftype == NL80211_IFTYPE_MONITOR) {
	// 	struct nlattr *flags;

	// 	flags = nla_nest_start(msg, NL80211_ATTR_MNTR_FLAGS);
	// 	if (!flags ||
	// 	    nla_put_flag(msg, NL80211_MNTR_FLAG_COOK_FRAMES))
	// 		goto fail;

	// 	nla_nest_end(msg, flags);
	// } else if (wds) {
	// 	if (nla_put_u8(msg, NL80211_ATTR_4ADDR, wds))
	// 		goto fail;
	// }

	/*
	 * Tell cfg80211 that the interface belongs to the socket that created
	 * it, and the interface should be deleted when the socket is closed.
	 */
	// if (nla_put_flag(msg, NL80211_ATTR_IFACE_SOCKET_OWNER))
	// 	goto fail;

	// if ((addr && iftype == NL80211_IFTYPE_P2P_DEVICE) &&
	//     nla_put(msg, NL80211_ATTR_MAC, ETH_ALEN, addr))
	// 	goto fail;

	//ret = send_and_recv_resp(drv, msg, handler, arg);
	// ret = send_and_recv(NULL, drv->common.nl, msg,
	// 		     handler, arg, NULL, NULL, NULL);
	// msg = NULL;
	// if (ret) {
	// fail:
	// 	nlmsg_free(msg);
	// 	wpa_printf(MSG_ERROR, "Failed to create interface %s: %d (%s)",
	// 		   ifname, ret, strerror(-ret));
	// 	return ret;
	// }

	ifidx = if_nametoindex(ifname);
	wpa_printf(MSG_DEBUG, "MIHAI: New interface %s created: ifindex=%d",
		   ifname, ifidx);

	if (ifidx <= 0)
		return -1;

	return ifidx;
}


int wired_create_iface(struct wpa_driver_wired_data *drv,
			 const char *ifname, enum wpa_driver_if_type iftype,
			 const u8 *addr, int wds,
			 int (*handler)(struct nl_msg *, void *),
			 void *arg, int use_existing)
{
	int ret = 0;

	 ret = wired_create_iface_once(drv, ifname, iftype, addr, wds, handler,
	 				arg);

	/* if error occurred and interface exists already */
	if (ret == -ENFILE && if_nametoindex(ifname)) {
		if (use_existing) {
			wpa_printf(MSG_DEBUG, "nl80211: Continue using existing interface %s",
				   ifname);
			if (addr /*&& iftype != NL80211_IFTYPE_MONITOR*/ &&
			    linux_set_ifhwaddr(drv->common.sock, ifname,
					       addr) < 0 &&
			    (linux_set_iface_flags(drv->common.sock,
						   ifname, 0) < 0 ||
			     linux_set_ifhwaddr(drv->common.sock, ifname,
						addr) < 0 ||
			     linux_set_iface_flags(drv->common.sock,
						   ifname, 1) < 0))
					return -1;
			return -ENFILE;
		}
		wpa_printf(MSG_INFO, "Try to remove and re-create %s", ifname);

		/* Try to remove the interface that was already there. */
		// wired_remove_iface(drv, if_nametoindex(ifname));

		/* Try to create the interface again */
		ret = wired_create_iface_once(drv, ifname, iftype, addr,
		 				wds, handler, arg);
	}

	return ret;
}


static int wpa_driver_wired_if_add(void *priv, enum wpa_driver_if_type type,
				     const char *ifname, const u8 *addr,
				     void *bss_ctx, void **drv_priv,
				     char *force_ifname, u8 *if_addr,
				     const char *bridge, int use_existing,
				     int setup_ap)
{
	//struct i802_bss *bss = priv;
	//struct wpa_driver_wired_data *drv = bss->drv;
	struct wpa_driver_wired_data *drv = priv;
	int ifidx;

	printf("MIHAI: wpa_driver_wired_if_add\n");
	printf("\t type=%d\n", type);
	printf("\t ifname=%s\n", ifname ? ifname : "null");
	printf("\t force_ifname=%s\n", force_ifname ? force_ifname : "null");
	printf("\t bridge=%s\n", bridge ? bridge : "null");

	if (addr)
		os_memcpy(if_addr, addr, ETH_ALEN);

	ifidx = wired_create_iface(drv, ifname, type, addr,
	 				     0, NULL, NULL, use_existing);

	return 0;
}


const struct wpa_driver_ops wpa_driver_wired_ops = {
	.name = "wired",
	.desc = "Wired Ethernet driver",
	.hapd_init = wired_driver_hapd_init,
	.hapd_deinit = wired_driver_hapd_deinit,
	.hapd_send_eapol = wired_send_eapol,
	.get_ssid = driver_wired_get_ssid,
	.get_bssid = driver_wired_get_bssid,
	.get_capa = driver_wired_get_capa,
	.init = wpa_driver_wired_init,
	.deinit = wpa_driver_wired_deinit,
	.if_add = wpa_driver_wired_if_add,
};
