//
//  pds-intercept.hpp
//  pds-project
//
//  Created by Jordán Jarolím on 22.04.17.
//  Copyright © 2017 FIT VUTBR. All rights reserved.
//

#ifndef pds_intercept_hpp
#define pds_intercept_hpp

#include <stdio.h>
#include <string>

#include "pds-scanner.hpp"
#include "pds-spoof.hpp"
#include "types.h"


#include <vector>



class PdsIntercept{
private:
    std::vector<tVictim> victims;
    
public:
    void catchTraffic(class PdsScanner *scanner);
    void forwardTraffic(const struct pcap_pkthdr *header, const u_char *buffer);

    
};
#endif /* pds_intercept_hpp */

