//
//  manipulateXml.cpp
//  pds-project
//
//  Created by Jordán Jarolím on 22.04.17.
//  Copyright © 2017 FIT VUTBR. All rights reserved.
//

#include "manipulateXml.hpp"
#include "pds-intercept.hpp"
#include <fstream>
#include <sstream>
#include <string.h>
#include "types.h"
#include <algorithm>




using namespace rapidxml;
using namespace std;

/* Prepare new empty xml */
void ManipulateXml::prepareXml(string filename){
    xml_document<> doc;
    
    xml_node<>* decl = doc.allocate_node(node_declaration);
    decl->append_attribute(doc.allocate_attribute("version", "1.0"));
    decl->append_attribute(doc.allocate_attribute("encoding", "utf-8"));
    doc.append_node(decl);
    
    xml_node<>* root = doc.allocate_node(node_element, "devices");
    doc.append_node(root);
    std::string xml_as_string;
    rapidxml::print(std::back_inserter(xml_as_string), doc);
    std::string xml_no_indent;
    rapidxml::print(std::back_inserter(xml_no_indent), doc, print_no_indenting);
    std::ofstream file_stored(filename);
    file_stored << doc;
    file_stored.close();
    doc.clear();
    
}

/* Create new node in xml */
void ManipulateXml::addHost(string mac, string ip, string filename){
    bool isNew = false;
    xml_document<> doc;
    std::ifstream file(filename);
    std::replace(mac.begin(), mac.end(), ':', '.');
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content(buffer.str());
    doc.parse<parse_declaration_node | parse_no_data_nodes>(&content[0]);
    
    xml_node<>* cur_node = doc.first_node("devices")->first_node();
    
    if (cur_node){
        string curMac = cur_node->first_attribute("mac")->value();
        isNew = true;
        while (cur_node){
            /* Multiple responses from one host - doesnt need to rewrite */
            if (!mac.compare(cur_node->first_attribute("mac")->value())){
                isNew = false;
            }
            cur_node = cur_node->next_sibling();
            if (cur_node)
                curMac = cur_node->first_attribute("mac")->value();
        }
    }else
        isNew = true;
    
    if (isNew){
        cout<<"Creating new host: MAC: "<<mac<<" IP: "<< ip<<"\n";
        xml_node<>* newHost = doc.allocate_node(node_element, "host");
        xml_node<>* newIP = doc.allocate_node(node_element, "ipv4");

        xml_attribute<> * xmlMac = doc.allocate_attribute("mac", mac.c_str());
        newHost->append_attribute(xmlMac);
        
        const char * xmlIP = doc.allocate_string(ip.c_str(), strlen(ip.c_str()));
        newIP->value(xmlIP);
        newHost->append_node(newIP);
        doc.first_node("devices")->append_node(newHost);
    }
    std::string xml_as_string;
    rapidxml::print(std::back_inserter(xml_as_string), doc);

    std::string xml_no_indent;
    rapidxml::print(std::back_inserter(xml_no_indent), doc, print_no_indenting);
    
    std::ofstream file_stored(filename);
    file_stored << doc;
    file_stored.close();
    doc.clear();
}

vector<tVictim> ManipulateXml::readVictims(string filename){
    tVictim victim = {"", "", ""};
    vector<tVictim> victims;
    
    xml_document<> doc;
    std::ifstream file(filename);
    
    std::stringstream buffer;
    buffer << file.rdbuf();
    std::string content(buffer.str());
    doc.parse<parse_declaration_node | parse_no_data_nodes>(&content[0]);
    
    xml_node<>* cur_node = doc.first_node("devices")->first_node();
    
    while (cur_node){
        if (cur_node->first_attribute("group")){
            victim.mac = cur_node->first_attribute("mac")->value();
            victim.group = cur_node->first_attribute("group")->value();
            victim.ip = cur_node->first_node("ipv4")->value();
            std::replace(victim.mac.begin(), victim.mac.end(), '.', ':');
            victims.push_back(victim);
        }
        cur_node = cur_node->next_sibling();
    }
    
    return victims;
}

