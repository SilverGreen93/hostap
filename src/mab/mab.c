
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
#include "ap/sta_info.h"
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
    struct mab_bridge *mb;
    int old_bridge_index;
    char old_bridge_name[IFNAMSIZ];

    dl_list_for_each(mb, &hapd->iconf->mab_interfaces, struct mab_bridge, list)
    {
        old_bridge_index = get_bridge_index(mb->br_ifindex);
        if (old_bridge_index > 0)
        {
            if_indextoname(old_bridge_index, old_bridge_name);
            br_delif(old_bridge_name, mb->br_name);
        }
        br_addif(hapd->iconf->parking_vlan, mb->br_name);
        set_interface_isolated(mb->br_ifindex);
    }
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


int add_mab_bridge(struct dl_list *list, char *bridge_name, int is_dynamic)
{
    struct mab_bridge *mb;
    int ifindex;

    ifindex = if_nametoindex(bridge_name);
    if (!ifindex)
    {
        return -2;
    }
    if (list_contains_bridge(list, ifindex, 0))
    {
        return -1;
    }

    mb = malloc(sizeof(struct mab_bridge));
    mb->br_ifindex = ifindex;
    os_strlcpy(mb->br_name, bridge_name, sizeof(mb->br_name));
    mb->is_dynamic = is_dynamic;
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


int list_contains_bridge(struct dl_list *list, int ifindex, int only_dynamic)
{
    int found = 0;
    struct mab_bridge *it;

    dl_list_for_each(it, list, struct mab_bridge, list)
    {
        found = 0;
        if (it->br_ifindex == ifindex)
        {
            if (!only_dynamic)
            {
                found = 1;
            }
            else if (it->is_dynamic)
            {
                found = 1;
            }
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
                // aici trebuie sa parcurgem lista de bridge-uri pe care este activat mab si in plus si bridge-urile pe care a fost autorizat un client
                if (list_contains_bridge(&hapd->iconf->mab_bridges_list, master_index, 0))
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

    printf("Inainte de remove:\n");
    print_list(&hapd->iconf->learned_mac_list);

    dl_list_for_each_safe(it, tmp, &hapd->iconf->learned_mac_list, struct learned_mac, list)
    {
        if (!it->valid)
        {
            // mutam portul in br0 doar daca macul a expirat de pe un alt bridge
            if (list_contains_bridge(&hapd->iconf->mab_bridges_list, it->br_ifindex, 1))
            {
                // struct sta_info *sta;
                // sta = ap_get_sta(hapd, it->mac);
                // if (sta) {
                char old_bridge_name[IFNAMSIZ];
                char bridge_name[IFNAMSIZ];
                char if_name[IFNAMSIZ];
                int old_bridge_index;
                if_indextoname(it->ifindex, if_name);
                old_bridge_index = get_bridge_index(it->ifindex);
                if_indextoname(old_bridge_index, old_bridge_name);
                // snprintf(bridge_name, sizeof(bridge_name), "br-%s", if_name);
                os_strlcpy(bridge_name, hapd->iconf->parking_vlan, sizeof(bridge_name));
                if (strcmp(bridge_name, old_bridge_name))
                {
                    wpa_printf(MSG_DEBUG, ">>>>>>>>>>>>>>>>>>>>> MIHAI: bag %s din %s in %s", if_name, old_bridge_name, bridge_name);
                    br_delif(old_bridge_name, if_name);
                    br_addif(bridge_name, if_name);
                    set_interface_isolated(it->ifindex);
                }
                //}
            }
            dl_list_del(&it->list);
            free(it);
        }
    }

    printf("Dupa remove:\n");
    print_list(&hapd->iconf->learned_mac_list);
    printf("************************************************\n");

    close(sockfd);
    return 0;
}


void *mac_learn_thread(void *arg)
{
    // char src[6] = {0x9c, 0x8e, 0x99, 0x2c, 0xaf, 0x78}; //adresa MAC a suplicantului
    struct hostapd_data *hapd = arg;
    // struct sta_info *sta;

    printf(">>>>>>>>>>>>>>>>>>>>> MIHAI: started mac_learn_thread\n");
    sleep(5);
    assign_ports_to_parking_vlan(hapd);
    sleep(5);

    dl_list_init(&hapd->iconf->learned_mac_list);

    // dl_list_init(&mab_bridges_list);
    // add_mab_bridge("br-eno49", 19, 0);
    // add_mab_bridge("br-eno51", 20, 0);

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