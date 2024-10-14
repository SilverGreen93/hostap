#ifndef MAB_H
#define MAB_H

#include <linux/rtnetlink.h>
#include <linux/if_bridge.h>

#include "ap/sta_info.h"

#ifndef IFLA_BRPORT_ISOLATED
#define IFLA_BRPORT_ISOLATED	33
#endif

#define BUFSIZE 8192

struct nl_req {
    struct nlmsghdr hdr;
    struct ndmsg ndm;
};

struct br_nl_req {
    struct nlmsghdr hdr;
    struct ifinfomsg ifi;
    char buf[BUFSIZE];
};

struct learned_mac {
    struct dl_list list;
    unsigned char mac[6];
    int ifindex;
    int br_ifindex;
    int valid;
};

struct mab_interface {
    struct dl_list list;
    char if_name[IFNAMSIZ + 1];
    int if_index;
};

void assign_ports_to_parking_vlan(struct hostapd_data *hapd);
int move_to_bridge(int if_index, const char *new_bridge);
void add_vid_to_ifindex(int ifindex, int vid);
int set_interface_isolated(int ifindex);
int add_mab_interface(struct dl_list *list, char *if_name);
void free_mab_interfaces(struct dl_list *list);
void free_learned_mac_list(struct dl_list *list_pt);
void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);
int list_contains_interface(struct dl_list *list, int ifindex);
int request_mac(struct hostapd_data *hapd);
int get_bridge_index(int ifindex);
void mab_receive(struct hostapd_data *hapd, const u8 *sa);
void send_mab_request(struct hostapd_data *hapd, struct sta_info *sta);

#endif
