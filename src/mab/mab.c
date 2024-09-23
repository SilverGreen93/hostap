
#include <stdio.h>
#include "mab.h"

void* mac_learn_thread(void* arg)
{
    //char src[6] = {0x9c, 0x8e, 0x99, 0x2c, 0xaf, 0x78}; //adresa MAC a suplicantului
	struct hostapd_data *hapd = arg;
	//struct sta_info *sta;

	printf(">>>>>>>>>>>>>>>>>>>>> MIHAI: started mac_learn_thread\n");
	sleep(5);
	assign_ports_to_parking_vlan(hapd);
	sleep(5);

	dl_list_init(&hapd->iconf->learned_mac_list);

	// dl_list_init(&mab_bridges_list);
	// add_mab_bridge("br-eno49", 19, 0);
	// add_mab_bridge("br-eno51", 20, 0);

	while (1) {
		request_mac(hapd);
		sleep(10);
	}
	
    return NULL;
}