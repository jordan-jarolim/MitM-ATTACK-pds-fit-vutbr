//
//  pds-spoof.hpp
//  pds-project
//
//  Created by Jordán Jarolím on 22.04.17.
//  Copyright © 2017 FIT VUTBR. All rights reserved.
//

#ifndef pds_spoof_hpp
#define pds_spoof_hpp

#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include "xml/rapidxml.hpp"
#include "xml/rapidxml_print.hpp"
#include <fstream>
#include <sstream>

#include "pds-scanner.hpp"
#include "packet.hpp"
#include "types.h"


extern bool regenerate;

class PdsSpoof{
public:
    void spoofIt(std::string interface, std::string ip1, std::string ip2, std::string mac1, std::string mac2, std::string myMac, unsigned int timer);

};
#endif /* pds_spoof_hpp */
