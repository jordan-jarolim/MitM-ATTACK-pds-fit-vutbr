//
//  main-spoof.cpp
//  pds-project
//
//  Created by Jordán Jarolím on 13.04.17.
//  Copyright © 2017 FIT VUTBR.
//

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include "pds-scanner.hpp"
#include "pds-spoof.hpp"
#include "packet.hpp"
#include "types.h"
#include <signal.h>
#include <stdlib.h>
#include <tuple>
#include <getopt.h>
#include <algorithm>


using namespace std;

/**
 * Signal handler
 */
void my_handler(int s){
    printf(" Caught signal %d\n",s);
    cout << "Regenerating cache\n";
    regenerate = true;
}

/**
 * Parse arguments
 */
tuple<string, int, string, string, string, string, string> getOptions(int argc, char *argv[]) {
    
    int c;
    string filename = (string)"output.xml";
    string interface = (string)"eth1";
    string protocol = (string)"";
    string v1IP = (string)"";
    string v2IP = (string)"";
    string v1Mac = (string)"";
    string v2Mac = (string)"";
    int interval = 1;
    int longIndex = 0;
    
    /* https://linuxprograms.wordpress.com/2012/06/22/c-getopt_long_only-example-accessing-command-line-arguments/*/ 
    static struct option long_options[] = {
        {"victim1ip",  required_argument, NULL, '1'},
        {"victim1mac", required_argument, NULL, '2'},
        {"victim2ip",  required_argument, NULL, '3'},
        {"victim2mac", required_argument, NULL, '4'},
        {NULL, 0, NULL, 0}
    };
    
    while ((c = getopt_long_only(argc,argv,"p:t:i:",long_options,&longIndex)) != -1) {
        switch (c) {
            
            case 't':
                interval = stoi(optarg);
                break;
            case 'p':
                protocol = string(optarg);
                if (protocol != "arp" && protocol == "ndp") {
                    cerr << "Sorry, this protocol has not been implemented :(" << endl;
                    exit (0);
                }
                break;
            case 'i':
                interface = string(optarg);
                break;
            case '1':
                v1IP = string(optarg);
                break;
            case '2':
                v1Mac = string(optarg);
                replace(v1Mac.begin(), v1Mac.end(), '.', ':');
                break;
            case '3':
                v2IP = string(optarg);
                break;
            case '4':
                v2Mac = string(optarg);
                replace(v2Mac.begin(), v2Mac.end(), '.', ':');
                break;
            default:
                cerr<<"unknown argument!\n";
                //exit(0);
        }
    }
    
    return make_tuple(interface, interval, protocol, v1IP, v1Mac, v2IP, v2Mac);
    
}

/**
 * Run scanning of network
 */
int main(int argc,char** argv)
{
    struct sigaction sigIntHandler;
    //interface, interval, protocol, v1IP, v1Mac, v2IP, v2Mac
    tuple<string, int, string, string, string, string, string> options = getOptions(argc, argv);
    
    PdsScanner* scanner = new PdsScanner(get<0>(options), "unknown");
    PdsSpoof* spoof = new PdsSpoof;
    regenerate = false;
    
    // Register handler
    sigIntHandler.sa_handler = my_handler;
    sigemptyset(&sigIntHandler.sa_mask);
    sigIntHandler.sa_flags = 0;
    
    sigaction(SIGINT, &sigIntHandler, NULL);
    
    
    scanner->resolveIPv4Network();
    spoof->spoofIt(get<0>(options), get<3>(options), get<5>(options), get<4>(options), get<6>(options), scanner->addresses.myMacStr, 10);
    
    delete scanner;
    delete spoof;
    
    return 0;
}




