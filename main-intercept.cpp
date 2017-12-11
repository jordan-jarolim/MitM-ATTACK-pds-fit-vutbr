//
//  main-intercept.cpp
//  pds-project
//
//  Created by Jordán Jarolím on 22.04.17.
//  Copyright © 2017 FIT VUTBR. All rights reserved.
//

#include <stdio.h>

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "pds-intercept.hpp"
#include "pds-scanner.hpp"
#include "pds-spoof.hpp"
#include "types.h"
#include <signal.h>
#include <stdlib.h>
#include <tuple>
#include <getopt.h>
#include <iostream>


using namespace std;

/**
 * Signal handler
 */
void my_handler(int s){
    printf(" Caught signal %d\n",s);
    exit(0);
}

/**
 * Parse arguments
 */
tuple<string, string> getOptions(int argc, char *argv[]) {
    int c;
    string filename = (string)"output.xml";
    string interface = (string)"eth1";
    bool isFilename = false;
    bool isInterface = false;
    
    opterr = 0;
    
    while ((c = getopt(argc, argv, "i:f:")) != -1) {
        switch (c) {
            case 'i':
                interface = std::string(optarg);
                isInterface = true;
                break;
            case 'f':
                filename = std::string(optarg);
                isFilename = true;
                break;
            default:
                cerr << "unknown option\n";
                exit(1);
        }
    }
    if (!isFilename)
        cerr << "Program will use default filename: output.xml\n";
    
    if (!isInterface)
        cerr << "Program will use default interface: eth1\n";
    
    return make_tuple(interface, filename);
    
}

/**
 * Run interception
 */
int main(int argc,char** argv)
{
    struct sigaction sigIntHandler;
    //interface, interval, protocol, v1IP, v1Mac, v2IP, v2Mac
    tuple<string, string> options = getOptions(argc, argv);
    
    PdsScanner* scanner = new PdsScanner(get<0>(options), get<1>(options));
    PdsIntercept* intercept = new PdsIntercept;
    
    // Register handler
    sigIntHandler.sa_handler = my_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    
    sigaction(SIGINT, &sigIntHandler, NULL);
    
    
    scanner->resolveIPv4Network();
    intercept->catchTraffic(scanner);
    
    delete scanner;
    delete intercept;
    return 0;

}

