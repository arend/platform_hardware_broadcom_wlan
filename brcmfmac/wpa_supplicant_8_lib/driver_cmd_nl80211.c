/*
 * Driver interaction with extended Linux CFG8021
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * Alternatively, this software may be distributed under the terms of BSD
 * license.
 *
 */

#include "hardware_legacy/driver_nl80211.h"
#include "wpa_supplicant_i.h"
#include "config.h"
#ifdef ANDROID
#include "android_drv.h"
#endif

#define MAX_WPSP2PIE_CMD_SIZE		512

typedef struct android_wifi_priv_cmd {
	char *buf;
	int used_len;
	int total_len;
} android_wifi_priv_cmd;

#ifdef BCM_GENL
struct family_data {
        const char *group;
        int id;
};

int send_and_recv_msgs(struct wpa_driver_nl80211_data *drv, struct nl_msg *msg,
		       int (*valid_handler)(struct nl_msg *, void *),
		       void *valid_data);

int driver_get_multicast_id(void *priv,
                               const char *family, const char *group);
/* attributes (variables): the index in this enum is used as a reference for the type,
 *             userspace application has to indicate the corresponding type
 *             the policy is used for security considerations
 */
enum {
        BCM_EVENT_UNSPEC,
        BCM_EVENT_SVC_FOUND,
        BCM_EVENT_DEV_FOUND,
        BCM_EVENT_DEV_LOST,
#ifdef CONFIG_BT_WIFI_HO
        BCM_EVENT_DEV_BT_WIFI_HO_REQ,
#endif
        BCM_EVENT_MAX
};

enum {
        BCM_GENL_ATTR_UNSPEC,
        BCM_GENL_ATTR_STRING,
        BCM_GENL_ATTR_MSG,
        __BCM_GENL_ATTR_MAX,
};
#define BCM_GENL_ATTR_MAX (__BCM_GENL_ATTR_MAX - 1)

/* commands: enumeration of all commands (functions),
 * used by userspace application to identify command to be ececuted
 */
enum {
        BCM_GENL_CMD_UNSPEC,
        BCM_GENL_CMD_MSG,
        __BCM_GENL_CMD_MAX,
};
#define BCM_GENL_CMD_MAX (__BCM_GENL_CMD_MAX - 1)

typedef struct bcm_event_hdr {
	u16 type;
	u16 len;
} bcm_hdr_t;

typedef struct bcm_dev_info {
        u16 band;
        u16 freq;
        s16 rssi;
        u16 ie_len;
        u8 bssid[ETH_ALEN];
} bcm_dev_info_t;

static int wpa_driver_handle_attr_data(struct wpa_driver_nl80211_data *drv,
					char *data, unsigned int len);
int wpa_driver_register_genl(void *priv);
int wpa_driver_unregister_genl(void *priv);
int family_handler(struct nl_msg *msg, void *arg);
static int no_seq_check(struct nl_msg *msg, void *arg);
#define GENLMSG_DATA(glh) ((char *)(NLMSG_DATA(glh) + GENL_HDRLEN))
#define GENLMSG_PAYLOAD(glh) ((char *)(NLMSG_PAYLOAD(glh, 0) - GENL_HDRLEN))
#define NLA_DATA(na) 	(void *) ((char *)(na) + NLA_HDRLEN)
#endif /* BCM_GENL */

static int drv_errors = 0;

static void wpa_driver_send_hang_msg(struct wpa_driver_nl80211_data *drv)
{
	drv_errors++;
	if (drv_errors > DRV_NUMBER_SEQUENTIAL_ERRORS) {
		drv_errors = 0;
		wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "HANGED");
	}
}

int wpa_driver_nl80211_driver_cmd(void *priv, char *cmd, char *buf,
				  size_t buf_len )
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	struct ifreq ifr;
	android_wifi_priv_cmd priv_cmd;
	int ret = 0;

	if (os_strcasecmp(cmd, "STOP") == 0) {
		linux_set_iface_flags(drv->global->ioctl_sock, bss->ifname, 0);
		wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "STOPPED");
	} else if (os_strcasecmp(cmd, "START") == 0) {
		linux_set_iface_flags(drv->global->ioctl_sock, bss->ifname, 1);
		wpa_msg(drv->ctx, MSG_INFO, WPA_EVENT_DRIVER_STATE "STARTED");
	} else if (os_strcasecmp(cmd, "MACADDR") == 0) {
		u8 macaddr[ETH_ALEN] = {};

		ret = linux_get_ifhwaddr(drv->global->ioctl_sock, bss->ifname, macaddr);
		if (!ret)
			ret = os_snprintf(buf, buf_len,
					  "Macaddr = " MACSTR "\n", MAC2STR(macaddr));
	} else { /* Use private command */
		wpa_printf(MSG_DEBUG, "%s: ignoring private command %s\n",
			   __func__, cmd);
	}
	return ret;
}

int wpa_driver_set_p2p_noa(void *priv, u8 count, int start, int duration)
{
	char buf[MAX_DRV_CMD_SIZE];

	memset(buf, 0, sizeof(buf));
	wpa_printf(MSG_DEBUG, "%s: Entry", __func__);
	snprintf(buf, sizeof(buf), "P2P_SET_NOA %d %d %d", count, start, duration);
	return wpa_driver_nl80211_driver_cmd(priv, buf, buf, strlen(buf)+1);
}

int wpa_driver_get_p2p_noa(void *priv, u8 *buf, size_t len)
{
	/* Return 0 till we handle p2p_presence request completely in the driver */
	return 0;
}

int wpa_driver_set_p2p_ps(void *priv, int legacy_ps, int opp_ps, int ctwindow)
{
	char buf[MAX_DRV_CMD_SIZE];

	memset(buf, 0, sizeof(buf));
	wpa_printf(MSG_DEBUG, "%s: Entry", __func__);
	snprintf(buf, sizeof(buf), "P2P_SET_PS %d %d %d", legacy_ps, opp_ps, ctwindow);
	return wpa_driver_nl80211_driver_cmd(priv, buf, buf, strlen(buf) + 1);
}

int wpa_driver_set_ap_wps_p2p_ie(void *priv, const struct wpabuf *beacon,
				 const struct wpabuf *proberesp,
				 const struct wpabuf *assocresp)
{
	char buf[MAX_WPSP2PIE_CMD_SIZE];
	struct wpabuf *ap_wps_p2p_ie = NULL;
	char *_cmd = "SET_AP_WPS_P2P_IE";
	char *pbuf;
	int ret = 0;
	int i;
	struct cmd_desc {
		int cmd;
		const struct wpabuf *src;
	} cmd_arr[] = {
		{0x1, beacon},
		{0x2, proberesp},
		{0x4, assocresp},
		{-1, NULL}
	};

	wpa_printf(MSG_DEBUG, "%s: Entry", __func__);
	for (i = 0; cmd_arr[i].cmd != -1; i++) {
		os_memset(buf, 0, sizeof(buf));
		pbuf = buf;
		pbuf += sprintf(pbuf, "%s %d", _cmd, cmd_arr[i].cmd);
		*pbuf++ = '\0';
		ap_wps_p2p_ie = cmd_arr[i].src ?
			wpabuf_dup(cmd_arr[i].src) : NULL;
		if (ap_wps_p2p_ie) {
			os_memcpy(pbuf, wpabuf_head(ap_wps_p2p_ie), wpabuf_len(ap_wps_p2p_ie));
			ret = wpa_driver_nl80211_driver_cmd(priv, buf, buf,
				strlen(_cmd) + 3 + wpabuf_len(ap_wps_p2p_ie));
			wpabuf_free(ap_wps_p2p_ie);
			if (ret < 0)
				break;
		}
	}

	return ret;
}

#ifdef BCM_GENL /* GENERIC NETLINK RECEIVE PATH */
static int no_seq_check(struct nl_msg *msg, void *arg)
{
	return NL_OK;
}

static void wpa_driver_recv_genl(int sock, void *eloop_ctx, void *handle)
{
	 struct wpa_driver_nl80211_data *drv = eloop_ctx;

        wpa_printf(MSG_ERROR, "BCM-GENL event available");

	if(drv->event_sock)
			nl_recvmsgs(drv->event_sock, nl_socket_get_cb(drv->event_sock));
	else
			wpa_printf(MSG_ERROR, "BCM-GENL event on wrong driver interface");
}

static int wpa_driver_handle_attr_data(struct wpa_driver_nl80211_data *drv,
					char *data, unsigned int len)
{
	bcm_hdr_t *hdr;
	u8 *addr = NULL;

	if(len <= sizeof(bcm_hdr_t)) {
		wpa_printf(MSG_ERROR, "LENGTH too SHORT!!!\n");
		return -EINVAL;
	}


	hdr = (bcm_hdr_t *)data;

	wpa_printf(MSG_ERROR, "BCM-GENL event_type:%x event_len: %x", hdr->type, hdr->len);

	wpa_hexdump(MSG_DEBUG, "Event_data dump:", (const u8 *)data, len);
	wpa_hexdump(MSG_ERROR, "Event_data dump:", (const u8 *)data, len);
	wpa_hexdump(MSG_ERROR, " ",(const u8 *)data+32, len-32);
	wpa_hexdump(MSG_ERROR, " ",(const u8 *)data+64, len-64);


	switch (hdr->type) {
#ifndef HOSTAPD
		case BCM_EVENT_SVC_FOUND:
			{
				wpa_printf(MSG_DEBUG, "BCM-GENL [SERVICE-FOUND]");

				break;
			}
		case BCM_EVENT_DEV_FOUND:
			{
				struct wpa_scan_results scan_res;
				struct wpa_scan_res *bss;
				u16 tot_len = 0;
				u8 *ptr = NULL;
				bcm_dev_info_t *info = (bcm_dev_info_t *)((u8 *)data +
							sizeof(bcm_hdr_t));

				wpa_printf(MSG_DEBUG, "BCM-GENL [DEV-FOUND] band:%x Freq %d"
					" rssi:%d ie_len:%x Mac:"MACSTR"\n",
					info->band, info->freq, info->rssi,
					 info->ie_len, MAC2STR(info->bssid));

				break;
			}

		case BCM_EVENT_DEV_LOST:
			{
				if(hdr->len != 6) {
					wpa_printf(MSG_ERROR, "DEV_LOST: invalid data"
						" (hdr_len != ETH_ALEN)");
					return -EINVAL;

				}

				wpa_printf(MSG_DEBUG, "BCM-GENL [DEV-LOST] "MACSTR,
					MAC2STR((u8 *)data + sizeof(bcm_hdr_t)));

				break;
			}
#endif /* HOSTAPD */
#ifdef CONFIG_BT_WIFI_HO
		case BCM_EVENT_DEV_BT_WIFI_HO_REQ:
			{
				union wpa_event_data event;
				setup_netinfo_t *ho_cmd = (setup_netinfo_t *)((u8 *)data +
								sizeof(bcm_hdr_t));
				wpa_printf(MSG_ERROR, "BT WIFI HANDOVER REQ RECEIVED FROM WPA_SUP: %d\n", ho_cmd->opmode);
				os_memset(&event, 0, sizeof(event));
				os_memcpy(&event.handover_command,ho_cmd,sizeof(setup_netinfo_t));
				if (ho_cmd->opmode == HO_MODE_GO) {
					wpa_supplicant_event(drv->ctx, EVENT_START_GO,&event);
				} else if (ho_cmd->opmode == HO_MODE_STA) {
					wpa_supplicant_event(drv->ctx, EVENT_STA2_GO,&event);
                                } else if (ho_cmd->opmode == HO_MODE_GC) {
                                        wpa_supplicant_event(drv->ctx, EVENT_GC2_GO,&event);
				} else if (ho_cmd->opmode == HO_MODE_STOP_GO) {
					wpa_supplicant_event(drv->ctx, EVENT_STOP_GO,&event);
				} else {
					wpa_printf(MSG_ERROR, "Unknown Handover Msg: %d\n", ho_cmd->opmode);
				}
				break;
			}
#endif
		default:
			wpa_printf(MSG_ERROR, "UNKNOWN Event Msg");
			break;
	}

	return 0;
}

static int wpa_driver_handle_genl_event(struct nl_msg *msg, void *arg)
{
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct genlmsghdr *gnlh = nlmsg_data(nlmsg_hdr(msg));
	struct nlattr *attrs[BCM_GENL_ATTR_MAX + 1];
	struct wpa_driver_nl80211_data *drv = (struct wpa_driver_nl80211_data *)arg;

	wpa_printf(MSG_DEBUG, "%s: Enter", __func__);

	if (nla_parse(attrs, BCM_GENL_ATTR_MAX,
		genlmsg_attrdata(gnlh, 0), genlmsg_attrlen(gnlh, 0), NULL) < 0) {
		wpa_printf(MSG_ERROR, "GENL msg parse failed");
		return -1;
	}

	if(attrs[BCM_GENL_ATTR_STRING]) {
		wpa_printf(MSG_ERROR, "BCM-GENL ATTR_STRING FOUND. Dumping the string");
		wpa_msg(drv->ctx, MSG_INFO, "%s", (char *)nla_data(attrs[BCM_GENL_ATTR_STRING]));
	} else if(attrs[BCM_GENL_ATTR_MSG]) {
		wpa_printf(MSG_ERROR, "BCM-GENL ATTR_MSG FOUND. Calling the handler");
		wpa_driver_handle_attr_data(drv, (char *)nla_data(attrs[BCM_GENL_ATTR_MSG]),
		nla_len(attrs[BCM_GENL_ATTR_MSG]));
	} else
		wpa_printf(MSG_ERROR, "BCM-GENL NOT Present");

	return NL_SKIP;

}

static int driver_genl_ctrl_resolve(struct nl_sock *handle,
                                     const char *name)
{
        /*
         * Android ICS has very minimal genl_ctrl_resolve() implementation, so
         * need to work around that.
         */
        struct nl_cache *cache = NULL;
        struct genl_family *nl80211 = NULL;
        int id = -1;

        if (genl_ctrl_alloc_cache(handle, &cache) < 0) {
                wpa_printf(MSG_ERROR, "nl80211: Failed to allocate generic "
                           "netlink cache");
                goto fail;
        }

        nl80211 = genl_ctrl_search_by_name(cache, name);
        if (nl80211 == NULL)
                goto fail;

        id = genl_family_get_id(nl80211);

	wpa_printf(MSG_ERROR, "Family id:%d", id);

fail:
        if (nl80211)
                genl_family_put(nl80211);
        if (cache)
                nl_cache_free(cache);

        return id;
}

/* XXX Not yet tested */
int driver_send_msg(void *priv, int len, const void *data)
{
        struct i802_bss *bss = priv;
        struct wpa_driver_nl80211_data *drv = bss->drv;
	struct nl_msg *msg;

	msg = nlmsg_alloc();
	genlmsg_put(msg, NL_AUTO_PID, NL_AUTO_SEQ, drv->event_family, 0, NLM_F_REQUEST,
			BCM_GENL_CMD_MSG, 1);

	nla_put(msg, BCM_GENL_ATTR_MSG, (size_t)len, data);

	// Send message over netlink socket
	nl_send_auto_complete(drv->event_sock, msg);

	nlmsg_free(msg);

	return 0;
}
static int wpa_driver_register_genl_multicast(void *priv)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	int mcast_id = 0;

	mcast_id = driver_get_multicast_id(priv,
                               "bcm-genl", "bcm-genl-mcast");

	if (mcast_id >= 0) {
                if(nl_socket_add_membership(drv->event_sock, mcast_id) < 0) {
			wpa_printf(MSG_ERROR, "%s: MULTICAST ID"
				" add membership failed\n", __func__);
			return -1;
		}

	}

	return mcast_id;

}

int wpa_driver_register_genl(void *priv)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;
	int ret = 0;
	static int family;
	struct sockaddr_nl src_addr;
	static int init_flag = 0;

	wpa_printf(MSG_ERROR, "%s: Enter  (PID: %d)", __func__, getpid());
	if (init_flag == 1) {
		wpa_printf(MSG_ERROR, "GENL Already registered/Initialized");
		return 0;
	}
	init_flag = 1;
	if(drv->event_sock) {
		wpa_printf(MSG_ERROR, "GENL Already registered/Initialized");
		return 0;
	}

	drv->event_sock = nl_socket_alloc();
	if(!drv->event_sock) {
		wpa_printf(MSG_ERROR, "nl_socket_alloc failed");
		return -1;
	}

	if(genl_connect(drv->event_sock) < 0) {
		wpa_printf(MSG_ERROR, "genl_connect failed");
		ret = -1;
		goto fail;
	}
	drv->event_family = driver_genl_ctrl_resolve(drv->event_sock, "bcm-genl");
	if(drv->event_family < 0) {
		wpa_printf(MSG_ERROR, "genl_ctrl_resolve failed ret:%d", drv->event_family);
		ret = -1;
		goto fail;
	}

	nl_cb_set(nl_socket_get_cb(drv->event_sock),
		 NL_CB_SEQ_CHECK, NL_CB_CUSTOM, no_seq_check, drv);
	nl_cb_set(nl_socket_get_cb(drv->event_sock),
		 NL_CB_VALID, NL_CB_CUSTOM, wpa_driver_handle_genl_event, drv);

	if (wpa_driver_register_genl_multicast(priv) < 0) {
		wpa_printf(MSG_ERROR, "genl_multicast register failed");
		ret = -1;
		goto fail;
	}

        eloop_register_read_sock(nl_socket_get_fd(drv->event_sock),
                                 wpa_driver_recv_genl, drv, NULL);

	return 0;

fail:
	wpa_printf(MSG_ERROR, "%s: Failed. Driver may not be supporting SDO", __func__);

	if(drv->event_sock)
		nl_socket_free(drv->event_sock);
	return ret;

}

int wpa_driver_unregister_genl(void *priv)
{
	struct i802_bss *bss = priv;
	struct wpa_driver_nl80211_data *drv = bss->drv;

	if(!drv->event_sock) {
		wpa_printf(MSG_ERROR, " No socket initialized on this interface");
		return -1;
	}

        eloop_unregister_read_sock(nl_socket_get_fd(drv->event_sock));

	nl_socket_free(drv->event_sock);
	drv->event_sock = NULL;

	return 0;
}

int driver_get_multicast_id(void *priv,
                               const char *family, const char *group)
{
        struct i802_bss *bss = priv;
        struct wpa_driver_nl80211_data *drv = bss->drv;
        struct nl_msg *msg;
        int ret = -1;
        struct family_data res = { group, -ENOENT };

        msg = nlmsg_alloc();
        if (!msg)
                return -ENOMEM;
        genlmsg_put(msg, 0, 0, genl_ctrl_resolve((struct nl_sock *)drv->global->nl, "nlctrl"),
                    0, 0, CTRL_CMD_GETFAMILY, 0);
        NLA_PUT_STRING(msg, CTRL_ATTR_FAMILY_NAME, family);

        ret = send_and_recv_msgs(drv, msg, family_handler, &res);
        msg = NULL;
        if (ret == 0) {
		wpa_printf(MSG_ERROR, "multicastid: %d", res.id);
                ret = res.id;
	} else
		wpa_printf(MSG_ERROR, "sendmsg returned %d", ret);

nla_put_failure:
        nlmsg_free(msg);
        return ret;
}

#endif  /* BCM_GENL */
