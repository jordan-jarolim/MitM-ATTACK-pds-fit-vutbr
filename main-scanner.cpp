//
//  main-scanner.cpp
//  pds-project
//
//  Created by Jordán Jarolím on 13.04.17.
//  Copyright © 2017 FIT VUTBR.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "pds-scanner.hpp"
#include "types.h"
#include <signal.h>
#include <stdlib.h>
#include <tuple>
#include <getopt.h>


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
 * Run scanning of network
 */
int main(int argc,char** argv)
{
    int returnValue;
    struct sigaction sigIntHandler;
    tuple<string, string> options = getOptions(argc, argv);
    
    // Register handler
    sigIntHandler.sa_handler = my_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    
    sigaction(SIGINT, &sigIntHandler, NULL);
    
    // Scan
    PdsScanner* scanner = new PdsScanner(get<0>(options), get<1>(options));
    returnValue = scanner->scanIPv4();
    delete scanner;
    
    return returnValue;
}




