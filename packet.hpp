//
//  packet.hpp
//  pds-project
//
//  Created by Jordán Jarolím on 21.04.17.
//  Copyright © 2017 FIT VUTBR. All rights reserved.
//

#ifndef packet_hpp
#define packet_hpp

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include "pds-scanner.hpp"
#include "types.h"


class Packet{
public:
    void sendPacket(pcap_t *pcap, unsigned char ethMacTarget[6], unsigned char ethMacSource[6], unsigned char arpMacTarget[6], unsigned char arpMacSource[6], std::string arpIpTarget, std::string arpIpSrc, unsigned short int operation);
    void simplifyMac(std::string mac_address, unsigned char simplifiedMac[6]);
    void saveHost(const struct pcap_pkthdr *header, const u_char *buffer);

};

#endif /* packet_hpp */
