//
//  manipulateXml.hpp
//  pds-project
//
//  Created by Jordán Jarolím on 22.04.17.
//  Copyright © 2017 FIT VUTBR. All rights reserved.
//

#ifndef manipulateXml_hpp
#define manipulateXml_hpp

#include <stdio.h>
#include "xml/rapidxml.hpp"
#include "xml/rapidxml_print.hpp"
#include <iostream>
#include <vector>
#include "pds-intercept.hpp"
#include "types.h"



class ManipulateXml{
public:
    static void prepareXml(std::string filename);
    static void addHost(std::string mac, std::string ip, std::string filename);
    static std::vector<tVictim> readVictims(std::string filename);

};

#endif /* manipulateXml_hpp */
