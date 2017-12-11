//
//  packet.cpp
//  pds-project
//
//  Created by Jordán Jarolím on 21.04.17.
//  Copyright © 2017 FIT VUTBR. All rights reserved.
//

#include "packet.hpp"
#include <netinet/if_ether.h>
#include "types.h"



#include "manipulateXml.hpp"

using namespace std;

/**
 * Send packet to network
 * Parameters ready to spoofing
 */
void Packet::sendPacket(pcap_t *pcap, unsigned char ethMacTarget[6], unsigned char ethMacSource[6], unsigned char arpMacTarget[6], unsigned char arpMacSource[6], string arpIpTarget, string arpIpSrc, unsigned short int operation){

    in_addr arpIpTargetAddr;
    in_addr arpIpSrcAddr;
    ether_header ethernet_header;
    ether_arp arp_header;
    
    if (!inet_aton(arpIpTarget.c_str(), &arpIpTargetAddr))
        exit(EXIT_FAILURE);
    if (!inet_aton(arpIpSrc.c_str(), &arpIpSrcAddr))
        exit(EXIT_FAILURE);
    
    /* Create eth + arp header according to params */
    memcpy(ethernet_header.ether_shost, ethMacSource, ETH_ALEN);
    ethernet_header.ether_type = htons(ETH_P_ARP);
    memcpy(ethernet_header.ether_dhost, ethMacTarget, ETH_ALEN);
    arp_header.arp_pro = htons(ETH_P_IP);
    arp_header.arp_hln = ETHER_ADDR_LEN;
    arp_header.arp_op = htons(operation);
    arp_header.arp_hrd = htons(ARPHRD_ETHER);
    arp_header.arp_pln = sizeof(in_addr_t);
    memcpy(&arp_header.arp_spa, &arpIpSrcAddr.s_addr, sizeof(arp_header.arp_spa));
    memcpy(&arp_header.arp_tpa, &arpIpTargetAddr.s_addr, sizeof(arp_header.arp_tpa));
    memcpy(&arp_header.arp_tha, arpMacTarget, sizeof(arp_header.arp_tha));
    memcpy(&arp_header.arp_sha, arpMacSource, sizeof(arp_header.arp_sha));
    
    /* Create packet */
    unsigned char packet[sizeof(struct ether_header)+sizeof(struct ether_arp)];
    memcpy(packet, &ethernet_header, sizeof(struct ether_header));
    memcpy(packet + sizeof(struct ether_header), &arp_header, sizeof(struct ether_arp));
    
    /* Send it */
    if (pcap_inject(pcap, packet, sizeof(packet)) < 0) {
        pcap_perror(pcap, 0);
        pcap_close(pcap);
        exit(EXIT_FAILURE);
    }
}

/* http://stackoverflow.com/questions/12772685/how-to-convert-mac-string-to-a-byte-address-in-c */
void Packet::simplifyMac(string macStr, unsigned char simplifiedMac[6]) {
    unsigned char mac[6];
    sscanf(macStr.c_str(), "%02hhx%02hhx:%02hhx%02hhx:%02hhx%02hhx", &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    memcpy(simplifiedMac,mac,sizeof(unsigned char)*6);
}

/* Save host to xml file */
void Packet::saveHost(const struct pcap_pkthdr *header, const u_char *packet)
{
    char macStr[18] = "\0";
    char ipStr[15] = "\0";
    ether_arp *arp_header = (struct ether_arp *) (packet + sizeof(ether_header));
    if (((ntohs(arp_header->ea_hdr.ar_hrd) == ARPHRD_ETHER) && (ntohs(arp_header->ea_hdr.ar_pro) == ETH_P_IP)) && (ntohs(arp_header->ea_hdr.ar_op) == ARPOP_REPLY)) {
        for (int i = 0; i < 6; i++)
            sprintf(macStr + strlen(macStr), "%02x%s", arp_header->arp_sha[i], (i % 2 == 1 && i < 5) ? ":" : "");

        for (int i = 0; i < 4; i++)
            sprintf(ipStr + strlen(ipStr), "%d%s", arp_header->arp_spa[i], i < 3 ? "." : "");

        /* Add it to a file */
        ManipulateXml::addHost(macStr, ipStr, PdsScanner::filename);
    }
}


