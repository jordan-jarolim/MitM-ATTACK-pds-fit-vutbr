//
//  pds-scanner.cpp
//  pds-project
//
//  Created by Jordán Jarolím on 13.04.17.
//  Copyright © 2017 FIT VUTBR. All rights reserved.
//

#include "pds-scanner.hpp"
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

#include "packet.hpp"
#include "types.h"


using namespace std;
using namespace rapidxml;
string PdsScanner::filename;
string PdsScanner::interface;


/**
 * Constructor
 */
PdsScanner::PdsScanner(string interface, string filename){
    this->interface = interface;
    this->filename = filename;
}

/**
 * pcal_loop handler
 */
void callback(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    ((Packet *)user)->saveHost(pkthdr, packet);
}

/** 
 * Get info about network to scan + my info
 */
void PdsScanner::resolveIPv4Network(){

    pcap_if_t *all;
    pcap_addr *oneIp;
    struct ifreq s;
    int fd;

    char error[PCAP_ERRBUF_SIZE] = "\0";

    /* Get IP assigned to interface + its mask - http://stackoverflow.com/questions/9443288/get-ip-adress-of-interface-in-linux-using-pcap */
    if (pcap_findalldevs(&all, error) != 0) {
        cerr << "Error: " << error << "\n";
        exit(EXIT_FAILURE);
    }

    for (pcap_if_t *d = all; d!=NULL; d = d->next) {
        if (!strcmp(d->name, interface.c_str())) {
            for (oneIp = d->addresses; oneIp!=NULL; oneIp = oneIp->next) {
                if (oneIp->addr->sa_family == AF_INET){
                    memcpy(&(addresses.myIPv4), oneIp->addr, sizeof(struct sockaddr));
                    memcpy(&(addresses.length), oneIp->netmask, sizeof(struct sockaddr));
            
                }
            }
        }
    }
    pcap_freealldevs(all);

    /* Get net IP - logical and between my address and mask */
    (addresses.netIP).sin_addr.s_addr = ((sockaddr_in *)(&(addresses.myIPv4)))->sin_addr.s_addr & ((sockaddr_in *)(&(addresses.length)))->sin_addr.s_addr;
    
    /* Get bcast address - http://stackoverflow.com/questions/777617/calculate-broadcast-address-from-ip-and-subnet-mask */
    addresses.bcast.sin_addr.s_addr = ((sockaddr_in *)(&(addresses.myIPv4)))->sin_addr.s_addr | (~ ((sockaddr_in *)(&(addresses.length)))->sin_addr.s_addr);
    
    
    /* Get mac address - http://stackoverflow.com/questions/1779715/how-to-get-mac-address-of-your-machine-using-a-c-program */
    fd = socket(PF_INET, SOCK_DGRAM, IPPROTO_IP);
    strcpy(s.ifr_name, interface.c_str());
    if (0 == ioctl(fd, SIOCGIFHWADDR, &s)) {
        int i;
        for (i = 0; i < 6; ++i)
            addresses.myMac.push_back(s.ifr_addr.sa_data[i]);
    }
    
    /* Save string representation of addresses */
    addresses.myIPv4Str = inet_ntoa(((sockaddr_in *)&(addresses.myIPv4))->sin_addr);
    addresses.netIPStr = inet_ntoa(addresses.netIP.sin_addr);
    addresses.bcastStr = inet_ntoa(addresses.bcast.sin_addr);

    /* convert byte representation of mac to string */
    for (int i = 0; i < 6; i++) {
        sprintf(addresses.myMacStr + strlen(addresses.myMacStr), "%02x%s", addresses.myMac[i], (i % 2 == 1 && i < 5) ? ":" : "");
    }
    
    /* Print it */
    cout << "myIP: "<< inet_ntoa(((sockaddr_in *)&(addresses.myIPv4))->sin_addr);
    cout << " netIP: "<< inet_ntoa(addresses.netIP.sin_addr);
    cout << " netMask: "<<inet_ntoa(((sockaddr_in *)&(addresses.length))->sin_addr);
    cout << " broadcast: "<<inet_ntoa(addresses.bcast.sin_addr);

    cout << " myMac: ";

    for (int i = 0; i < addresses.myMac.size(); i++)
        printf(":%02x", (unsigned char) addresses.myMac[i]);
    
    cout<<"\n";
}

void PdsScanner::getHosts(){
    
    /* Prepare xml file */
    ManipulateXml::prepareXml(filename);
    
    /* Prepare pcaps for child */
    char error_buffer[PCAP_ERRBUF_SIZE] = "\0";
    pcap_t *pcapChild = pcap_open_live(this->interface.c_str(), sizeof(struct ether_header) + sizeof(struct ether_arp), true, 0, error_buffer);
    
    /* Prepare pcaps for parent */
    struct bpf_program filter;
    
    pcap_t *pcapParent = pcap_open_live(this->interface.c_str(), sizeof(struct ether_header) + sizeof(struct ether_arp), true, 1000, error_buffer);
    
    /* Create filter */
    if (pcap_compile(pcapParent, &filter, "arp", 1, (bpf_u_int32)((sockaddr_in *)&(addresses.length))->sin_addr.s_addr) < 0)
        exit(EXIT_FAILURE);
    
    /* Load filter */
    if (pcap_setfilter(pcapParent, &filter) < 0)
        exit(EXIT_FAILURE);
    
    /* One process to send ARP, another to recieve them */
    pid_t pid = fork();
    
    if (pid < 0)
        exit(EXIT_FAILURE);
    else
        cout << "fork OK\n";
    
    Packet *packet = new Packet;
    if (pid == 0) {
        unsigned char byteBcastMac[6];
        unsigned char byteMyMac[6];

        
        sockaddr_in target = addresses.netIP;
        while (target.sin_addr.s_addr < addresses.bcast.sin_addr.s_addr - ntohl((uint32_t)1)){
            target.sin_addr.s_addr = target.sin_addr.s_addr + ntohl((uint32_t)1);
            if (target.sin_addr.s_addr != ((sockaddr_in *)&(addresses.myIPv4))->sin_addr.s_addr){
                packet->simplifyMac(BCASTMAC, byteBcastMac);
                packet->simplifyMac(addresses.myMacStr, byteMyMac);
                packet->sendPacket(pcapChild, byteBcastMac, byteMyMac, byteBcastMac, byteMyMac, inet_ntoa(target.sin_addr), addresses.myIPv4Str, ARPOP_REQUEST);
            }
        }
        pcap_close(pcapChild);
    } else {
        /* http://www.tcpdump.org/pcap.html */
        pcap_loop(pcapParent, -1, callback, reinterpret_cast<u_char*>(packet));
        pcap_close(pcapParent);
    }
    delete packet;
}

/**
 * Scan ipv4 network, ipv6 has not been implemented yet
 */
int PdsScanner::scanIPv4(){
    
    this->resolveIPv4Network();
    this->getHosts();
    return 0;
}
