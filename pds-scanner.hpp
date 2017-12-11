//
//  pds-scanner.hpp
//  pds-project
//
//  Created by Jordán Jarolím on 13.04.17.
//  Copyright © 2017 FIT VUTBR. All rights reserved
//

#ifndef pds_scanner_hpp
#define pds_scanner_hpp

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>           
#include <string>
#include <iostream>
#include <pcap/pcap.h>
#include <arpa/inet.h>
#include <errno.h>
#include <vector>
#include "manipulateXml.hpp"
#include "types.h"


#define BCASTMAC "ffff:ffff:ffff"

class PdsScanner{
private:
    int createArpPacket();
    void getHosts();


public:
    PdsScanner(std::string interface, std::string filename);
    static std::string filename;
    static std::string interface;
    struct tAddresses{
        std::vector<unsigned char> myMac;
        std::string myIPv4Str, netIPStr, bcastStr;
        sockaddr myIPv4, length;
        sockaddr_in netIP, bcast;
        char myMacStr[18];
    }addresses;
    
    void resolveIPv4Network();
    int scanIPv6();
    int scanIPv4();

};

#endif /* pds_scanner_hpp */
