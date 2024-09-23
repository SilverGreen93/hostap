#ifndef MAB_H
#define MAB_H

#include <net/if.h>
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <stdbool.h>
#include <string.h>
#include <netinet/in.h>
#include "utils/common.h"
#include "utils/list.h"
#include "ap/hostapd.h"

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

struct mab_bridge {
    struct dl_list list;
	char br_name[IFNAMSIZ];
	int br_ifindex;
    int is_dynamic;
};

int set_interface_isolated(int ifindex);
int add_mab_bridge(struct dl_list *list, char *bridge_name, int is_dynamic);
void parse_rtattr(struct rtattr *tb[], int max, struct rtattr *rta, int len);
int list_contains_bridge(struct dl_list *list, int ifindex, int only_dynamic);
int request_mac(struct hostapd_data *hapd);
void* mac_learn_thread(void* arg);

#endif