
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>

#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "utils/common.h"
#include "utils/list.h"
#include "ap/hostapd.h"
#include "radius/radius.h"
#include "radius/radius_client.h"
#include "eap_server/eap.h"
#include "eapol_auth/eapol_auth_sm.h"
#include "eapol_auth/eapol_auth_sm_i.h"

#include "mab.h"


static void print_mac_address(unsigned char *addr)
{
    for (int i = 0; i < 6; i++)
    {
        if (i > 0)
            printf(":");
        printf("%02x", addr[i]);
    }
    printf("\n");
}


static void print_list(struct dl_list *head)
{
    struct learned_mac *t;
    printf("Lista contine:\n");
    dl_list_for_each(t, head, struct learned_mac, list)
        printf("%02hhx:%02hhx:%02hhx:%02hhx:%02hhx:%02hhx (%d) ",
               t->mac[0], t->mac[1], t->mac[2], t->mac[3], t->mac[4], t->mac[5], t->valid);

    printf("\n(len=%d%s)\n", dl_list_len(head), dl_list_empty(head) ? " empty" : "");
}


static void assign_ports_to_parking_vlan(struct hostapd_data *hapd)
{
    struct mab_interface *mb;
    int old_bridge_index;
    char old_bridge_name[IFNAMSIZ];

    dl_list_for_each(mb, &hapd->iconf->mab_interfaces, struct mab_interface, list)
    {
        old_bridge_index = get_bridge_index(mb->if_index);
        if (old_bridge_index > 0)
        {
            if_indextoname(old_bridge_index, old_bridge_name);
            br_delif(old_bridge_name, mb->if_name);
        }
        br_addif(hapd->iconf->parking_vlan, mb->if_name);
        set_interface_isolated(mb->if_index);
    }
}


int move_to_bridge(int if_index, char *new_bridge)
{
    char old_bridge[IFNAMSIZ];
    char if_name[IFNAMSIZ];
    int old_index;
    int new_index;

    if_indextoname(if_index, if_name);
    old_index = get_bridge_index(if_index);
    if_indextoname(old_index, old_bridge);
    new_index = if_nametoindex(new_bridge);

    if (new_index != old_index) {
        wpa_printf(MSG_DEBUG, "MAB: Moving %s from %s to %s", if_name, old_bridge, new_bridge);
        br_delif(old_bridge, if_name);
        br_addif(new_bridge, if_name);
    }

    return 0;
}


int move_to_vlan(int if_index, int vlan_id)
{
    char new_bridge[IFNAMSIZ];

    snprintf(new_bridge, sizeof(new_bridge), "br%d", vlan_id);

    return move_to_bridge(if_index, new_bridge);
}


int set_interface_isolated(int ifindex)
{

    int sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0)
    {
        perror("socket");
        return 1;
    }

    struct
    {
        struct nlmsghdr nlh;
        struct ifinfomsg ifi;
        char buf[BUFSIZE];
    } req;

    memset(&req, 0, sizeof(req));
    req.nlh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nlh.nlmsg_flags = NLM_F_REQUEST;
    req.nlh.nlmsg_type = RTM_SETLINK;
    req.ifi.ifi_family = PF_BRIDGE;
    req.ifi.ifi_index = ifindex;

    struct rtattr *rta = (struct rtattr *)(((char *)&req) + NLMSG_ALIGN(req.nlh.nlmsg_len));
    rta->rta_type = IFLA_PROTINFO | NLA_F_NESTED;
    rta->rta_len = RTA_LENGTH(0);

    struct rtattr *nested = (struct rtattr *)(((char *)rta) + RTA_ALIGN(rta->rta_len));
    nested->rta_type = IFLA_BRPORT_ISOLATED;
    nested->rta_len = RTA_LENGTH(sizeof(__u8));

    __u8 isolated = 1;
    memcpy(RTA_DATA(nested), &isolated, sizeof(isolated));

    rta->rta_len = RTA_ALIGN(rta->rta_len) + RTA_ALIGN(nested->rta_len);
    req.nlh.nlmsg_len = NLMSG_ALIGN(req.nlh.nlmsg_len) + RTA_ALIGN(rta->rta_len);

    struct sockaddr_nl sa = {
        .nl_family = AF_NETLINK,
    };

    if (sendto(sock, &req, req.nlh.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        perror("sendto");
        close(sock);
        return 1;
    }

    close(sock);

    return 0;
}


int add_mab_interface(struct dl_list *list, char *if_name)
{
    struct mab_interface *mb;
    int ifindex;

    ifindex = if_nametoindex(if_name);
    if (!ifindex)
    {
        return -2;
    }
    if (list_contains_interface(list, ifindex))
    {
        return -1;
    }

    mb = malloc(sizeof(struct mab_interface));
    mb->if_index = ifindex;
    os_strlcpy(mb->if_name, if_name, sizeof(mb->if_name));
    dl_list_add(list, &mb->list);

    return 0;
}


void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len)
{
    memset(tb, 0, sizeof(struct rtattr *) * (max + 1));
    while (RTA_OK(rta, len))
    {
        if (rta->rta_type <= max)
            tb[rta->rta_type] = rta;
        rta = RTA_NEXT(rta, len);
    }
}


int list_contains_interface(struct dl_list *list, int ifindex)
{
    int found = 0;
    struct mab_interface *it;

    dl_list_for_each(it, list, struct mab_interface, list)
    {
        found = 0;
        if (it->if_index == ifindex)
        {
            found = 1;
            break;
        }
    }

    return found;
}


int request_mac(struct hostapd_data *hapd)
{
    int sockfd;
    struct sockaddr_nl sa;
    struct nl_req req;
    char buf[BUFSIZE];
    struct iovec iov;
    struct msghdr msg;
    struct nlmsghdr *nh;
    struct ndmsg *ndm;
    struct rtattr *rta;
    int len;
    struct learned_mac *it, *tmp;

    sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sockfd < 0)
    {
        perror("socket");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (bind(sockfd, (struct sockaddr *)&sa, sizeof(sa)) < 0)
    {
        perror("bind");
        close(sockfd);
        return -1;
    }

    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ndmsg));
    req.hdr.nlmsg_type = RTM_GETNEIGH;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.ndm.ndm_family = AF_BRIDGE;

    iov.iov_base = &req;
    iov.iov_len = req.hdr.nlmsg_len;
    memset(&msg, 0, sizeof(msg));
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;

    if (sendmsg(sockfd, &msg, 0) < 0)
    {
        perror("sendmsg");
        close(sockfd);
        return -1;
    }

    // invalidam lista inainte de parcurgerea MAC-urilor
    dl_list_for_each(it, &hapd->iconf->learned_mac_list, struct learned_mac, list)
        it->valid = 0;

    // while (1) {
    len = recv(sockfd, buf, sizeof(buf), 0);
    if (len < 0)
    {
        perror("recv");
        close(sockfd);
        return -1;
    }

    for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len))
    {
        if (nh->nlmsg_type == NLMSG_DONE)
            break;
        if (nh->nlmsg_type == NLMSG_ERROR)
        {
            fprintf(stderr, "Error in netlink message\n");
            close(sockfd);
            return -1;
        }

        ndm = NLMSG_DATA(nh);
        rta = (struct rtattr *)((char *)ndm + NLMSG_ALIGN(sizeof(struct ndmsg)));
        int rta_len = nh->nlmsg_len - NLMSG_LENGTH(sizeof(struct ndmsg));
        struct rtattr *tb[NDA_MAX + 1];
        parse_rtattr(tb, NDA_MAX, rta, rta_len);

        if (tb[NDA_LLADDR] && tb[NDA_MASTER] && (ndm->ndm_state & NUD_REACHABLE))
        {
            int master_index = *(int *)RTA_DATA(tb[NDA_MASTER]);
            int if_index = ndm->ndm_ifindex;
            char master_name[IF_NAMESIZE];
            char if_name[IF_NAMESIZE];
            if_indextoname(master_index, master_name);
            if_indextoname(if_index, if_name);
            if (master_index && if_index)
            {
                // learn mac only if the ifindex of the port is in the configured ports list
                if (list_contains_interface(&hapd->iconf->mab_interfaces, if_index))
                {
                    unsigned char *addr;
                    int addr_len;
                    int found = 0;

                    addr = (unsigned char *)RTA_DATA(tb[NDA_LLADDR]);
                    addr_len = RTA_PAYLOAD(tb[NDA_LLADDR]);

                    printf(">>>>>>>> Bridge: %s (%d), IF: %s (%d) MAC Address: ", master_name, master_index, if_name, if_index);
                    print_mac_address(addr);

                    dl_list_for_each(it, &hapd->iconf->learned_mac_list, struct learned_mac, list)
                    {
                        found = 0;
                        if (memcmp(it->mac, addr, addr_len) == 0)
                        {
                            found = 1;
                            it->valid = 1;
                            it->ifindex = if_index; // in varianta in care actualizam aici, nu se mai re-trimite la radius request cind se muta pe noul bridge
                            it->br_ifindex = master_index;
                            break;
                        }
                    }

                    if (!found)
                    {
                        struct learned_mac *new_mac;
                        new_mac = (struct learned_mac *)malloc(sizeof(struct learned_mac));
                        memcpy(new_mac->mac, addr, addr_len);
                        new_mac->ifindex = if_index;
                        new_mac->br_ifindex = master_index;
                        new_mac->valid = 1;
                        dl_list_add(&hapd->iconf->learned_mac_list, &new_mac->list);

                        // apelez eveniment de new mac
                        union wpa_event_data event;
                        os_memset(&event, 0, sizeof(event));
                        event.new_sta.addr = addr;
                        event.new_sta.ifindex = if_index;
                        wpa_supplicant_event(hapd, EVENT_NEW_STA, &event);
                        wpa_supplicant_event(hapd, EVENT_MAB_RX, &event);
                    }
                }
                else
                {
                    printf(">>>>>>>>> Skipping bridge ifindex = %d\n", master_index);
                }
            }
        }
    }

    // if (nh->nlmsg_flags & NLM_F_MULTI) {
    //     continue;
    // } else {
    //     break;
    // }
    //}

    printf("learned_mac_list:\n");
    print_list(&hapd->iconf->learned_mac_list);

    dl_list_for_each_safe(it, tmp, &hapd->iconf->learned_mac_list, struct learned_mac, list)
    {
        if (!it->valid)
        {
            int prk_index = if_nametoindex(hapd->iconf->parking_vlan);
            //move the port in the parking_vlan only if if was learnt and removed from any other bridge
            //if the MAC expired from the parking_vlan, this is normal, as it was likely moved to a new vlan
            if (it->br_ifindex != prk_index)
            {
                move_to_bridge(it->ifindex, hapd->iconf->parking_vlan);
            }
            dl_list_del(&it->list);
            free(it);
        }
    }

    close(sockfd);
    return 0;
}


void *mac_learn_thread(void *arg)
{
    struct hostapd_data *hapd = arg;

    wpa_printf(MSG_INFO, "MAB: Starting MAC learning thread");
    sleep(5);
    assign_ports_to_parking_vlan(hapd);
    sleep(5);

    dl_list_init(&hapd->iconf->learned_mac_list);

    while (1)
    {
        request_mac(hapd);
        sleep(10);
    }

    return NULL;
}


int get_bridge_index(int ifindex) {
    int sockfd;
    struct sockaddr_nl sa;
    struct br_nl_req req;
    char buf[BUFSIZE];
    struct iovec iov = { buf, sizeof(buf) };
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
    struct nlmsghdr *nh;
    struct ifinfomsg *ifi;
    struct rtattr *tb[IFLA_MAX + 1];

    sockfd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sockfd < 0) {
        perror("socket");
        return -1;
    }

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    memset(&req, 0, sizeof(req));
    req.hdr.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.hdr.nlmsg_type = RTM_GETLINK;
    req.hdr.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.hdr.nlmsg_seq = 1;
    req.ifi.ifi_family = AF_UNSPEC;

    if (send(sockfd, &req, req.hdr.nlmsg_len, 0) < 0) {
        perror("send");
        close(sockfd);
        return -1;
    }

    while (1) {
        int len = recv(sockfd, buf, sizeof(buf), 0);
        if (len < 0) {
            perror("recv");
            break;
        }

        for (nh = (struct nlmsghdr *)buf; NLMSG_OK(nh, len); nh = NLMSG_NEXT(nh, len)) {
            if (nh->nlmsg_type == NLMSG_DONE)
                return -1;

            if (nh->nlmsg_type == NLMSG_ERROR) {
                fprintf(stderr, "Netlink error\n");
                return -1;
            }

            ifi = NLMSG_DATA(nh);
            parse_rtattr(tb, IFLA_MAX, IFLA_RTA(ifi), nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi)));

            if (ifi->ifi_index == ifindex && tb[IFLA_MASTER]) {
                close(sockfd);
                return *(int *)RTA_DATA(tb[IFLA_MASTER]);
            }
        }
    }

    close(sockfd);
    return -1;
}

//bazat pe ieee802_1x_receive
void mab_receive(struct hostapd_data *hapd, const u8 *sa)
{
    struct sta_info *sta;

    sta = ap_get_sta(hapd, sa);

    if (!sta->eapol_sm) {
		sta->eapol_sm = ieee802_1x_alloc_eapol_sm(hapd, sta);
		if (!sta->eapol_sm)
			return;      
		sta->eapol_sm->eap_if->portEnabled = true;
	}
   
    //sta->eapol_sm->flags &= ~EAPOL_SM_WAIT_START;
    //sta->eapol_sm->eapolStart = true;
    sta->eapol_sm->is_mab_auth = true;
	sta->eapol_sm->is_mab_auth_sent = false;

    eapol_auth_step(sta->eapol_sm);
}

// bazat pe ieee802_1x_encapsulate_radius
void send_mab_request(struct hostapd_data *hapd, struct sta_info *sta)
{

    struct eapol_state_machine *sm = sta->eapol_sm;
    struct radius_msg *msg;
    char identity[15];
    size_t identity_len;

	if (!sm)
		return;

	//stabilire identitate si parola dupa mac
	snprintf(identity, sizeof(identity), "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
		sta->addr[0], sta->addr[1], sta->addr[2], sta->addr[3], sta->addr[4], sta->addr[5]);
    identity_len = strlen(identity);
    
	wpa_printf(MSG_DEBUG, ">>>>>>>>>>>>>>>>>>>>> MIHAI: pachet RADIUS MAB pt: %s", identity);

    sm->radius_identifier = radius_client_get_id(hapd->radius);
    msg = radius_msg_new(RADIUS_CODE_ACCESS_REQUEST, sm->radius_identifier);
    if (!msg) {
		wpa_printf(MSG_INFO, "MIHAI: Could not create new RADIUS packet");
		return;
	}

    if (radius_msg_make_authenticator(msg) < 0) {
		wpa_printf(MSG_INFO, "MIHAI: Could not make Request Authenticator");
		goto fail;
	}

	if (!radius_msg_add_msg_auth(msg))
		goto fail;

	if (!radius_msg_add_attr(msg, RADIUS_ATTR_USER_NAME, identity, identity_len)) {
		wpa_printf(MSG_INFO, "MIHAI: Could not add User-Name");
		goto fail;
	}

  	if (!radius_msg_add_attr_user_password(
		    msg, (u8 *) identity, identity_len,
            hapd->conf->radius->auth_server->shared_secret,
            hapd->conf->radius->auth_server->shared_secret_len)) {
		wpa_printf(MSG_INFO, "MIHAI: Could not add User-Password");
		goto fail;
    }

    if (add_common_radius_attr(hapd, hapd->conf->radius_auth_req_attr, sta, msg) < 0)
	    goto fail;

    //SQL lite nu este activat
	//if (sta && add_sqlite_radius_attr(hapd, sta, msg, 0) < 0)
	//	goto fail;

	if (!hostapd_config_get_radius_attr(hapd->conf->radius_auth_req_attr, RADIUS_ATTR_FRAMED_MTU) &&
	    !radius_msg_add_attr_int32(msg, RADIUS_ATTR_FRAMED_MTU, 1400)) {
		wpa_printf(MSG_INFO, "MIHAI: Could not add Framed-MTU");
		goto fail;
	}

	if (radius_client_send(hapd->radius, msg, RADIUS_AUTH, sta->addr) < 0)
		goto fail;
    wpa_printf(MSG_DEBUG, ">>>>>>>>>>>>>>>>>>>>> MIHAI: Trimis mesaj la RADIUS");

	return;

fail:
    wpa_printf(MSG_INFO, ">>>>>>>>>>>>>>>>>>>>> MIHAI: FAIL");
	radius_msg_free(msg);
}