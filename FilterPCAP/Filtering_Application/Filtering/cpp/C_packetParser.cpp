#include <iostream>
#include "headers/C_packetParser.h"

using namespace std;

// TCP flags information.
string C_packetParser::print_tcp_flags(pcpp::TcpLayer* tcpLayer){ 
    std::string result = "";
    if (tcpLayer->getTcpHeader()->synFlag == 1)
        result += "SYN ";
    if (tcpLayer->getTcpHeader()->ackFlag == 1)
        result += "ACK ";
    if (tcpLayer->getTcpHeader()->pshFlag == 1)
        result += "PSH ";
    if (tcpLayer->getTcpHeader()->cwrFlag == 1)
        result += "CWR ";
    if (tcpLayer->getTcpHeader()->urgFlag == 1)
        result += "URG ";
    if (tcpLayer->getTcpHeader()->eceFlag == 1)
        result += "ECE ";
    if (tcpLayer->getTcpHeader()->rstFlag == 1)
        result += "RST ";
    if (tcpLayer->getTcpHeader()->finFlag == 1)
        result += "FIN ";
    
    return result;
}

// To extract the protocol type of any layer.
string C_packetParser::get_protocol(pcpp::ProtocolType protocolType){
    switch (protocolType){
        case pcpp::Ethernet:
            return "Ethernet";
        case pcpp::IPv4:
            return "IPv4";
        case pcpp::TCP:
            return "TCP";
        case pcpp::UDP:
            return "UDP";
        case pcpp::ICMP:
            return "ICMP";
        case pcpp::ARP:
            return "ARP";
        case pcpp::VLAN:
            return "VLAN";
        case pcpp::DNS:
            return "DNS";
        case pcpp::SSL:
            return "SSL";
        case pcpp::HTTPRequest:
        case pcpp::HTTPResponse:
            return "HTTP";
        default:
            return "Unknown";
    }
}

// information which is returned as string are stored in character array here.
void C_packetParser::string_to_charArray(string str, char cArr[]){ 
    int iterator_copy_string_to_charArray = 0;
    while(str[ iterator_copy_string_to_charArray ] != '\0'){
        cArr[ iterator_copy_string_to_charArray ] = str[iterator_copy_string_to_charArray];
        iterator_copy_string_to_charArray++;
    }
    cArr[ iterator_copy_string_to_charArray ] = '\0';
    return;
}

// all packet info will be stored in packetInfo.
bool C_packetParser::single_packet_parser(uint8_t* PayL, int packet_length, timeval timestamp, C_packet_information &packetInfo){
    pcpp::RawPacket rp(PayL, packet_length, timestamp, false);
    pcpp::Packet parsedPacket(&rp);
    pcpp::Layer* curLayer = parsedPacket.getFirstLayer();
    packetInfo.packet_length = (int)curLayer->getDataLen(); // extract packet length.
    
    pcpp::EthLayer* ethernetLayer = parsedPacket.getLayerOfType<pcpp::EthLayer>(); // get ethernet layer.
    if (ethernetLayer == NULL){
        printf("Something went wrong, couldn't find Ethernet layer\n");
        return false;
    }
    
    string_to_charArray(ethernetLayer->getSourceMac().toString().c_str(),packetInfo.source_macAddress); // SRC MAC Address
    string_to_charArray(ethernetLayer->getDestMac().toString().c_str(), packetInfo.destination_macAddress);// DSNT MAC ADRES
    packetInfo.ethernet_type  =  (ntohs(ethernetLayer->getEthHeader()->etherType));// type of ethernet.
    curLayer = curLayer->getNextLayer();
    
    if(ntohs(ethernetLayer->getEthHeader()->etherType) == IPv4_Type) { // if IPv4 Type
        
        pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
        if (ipLayer == NULL){
            printf("Something went wrong, couldn't find IPv4 layer\n");
            return false;
        }
        
        string_to_charArray(ipLayer->getSrcIpAddress().toString().c_str(), packetInfo.source_ipAddress);
        string_to_charArray(ipLayer->getDstIpAddress().toString().c_str(), packetInfo.destination_ipAddress);
        
    }
    else if(ntohs(ethernetLayer->getEthHeader()->etherType) == IPv6_Type){ // If IPv6 Type
        
        pcpp::IPv6Layer* ipLayer_v6 = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
        if (ipLayer_v6 == NULL){
            printf("Something went wrong, couldn't find IPv6 layer\n");
            return false;
        }
        
        string_to_charArray(ipLayer_v6->getSrcIpAddress().toString().c_str(),packetInfo.source_ipAddress);
        string_to_charArray(ipLayer_v6->getDstIpAddress().toString().c_str(), packetInfo.destination_ipAddress);
    }
    else if(ntohs(ethernetLayer->getEthHeader()->etherType) == ARP_Type){ // ARP Type.
        pcpp::ArpLayer* arpLayer = parsedPacket.getLayerOfType<pcpp::ArpLayer>();
        
        string_to_charArray(arpLayer->getSenderIpAddr().toString().c_str(), packetInfo.source_ipAddress);
        
        string_to_charArray(arpLayer->getTargetIpAddr().toString().c_str(), packetInfo.destination_ipAddress);
        
        string_to_charArray(get_protocol(curLayer->getProtocol()).c_str(), packetInfo.protocol);
        
        return true;
    }
    
    if(curLayer->getNextLayer()!= NULL){
        curLayer = curLayer->getNextLayer();
        
        string_to_charArray(get_protocol(curLayer->getProtocol()).c_str(),packetInfo.protocol);
        
        if(curLayer->getProtocol() == ICMPv6_Type){ // ICMPv6 type.
            string protocol_ICMPv6 = "ICMPv6";
            string_to_charArray(protocol_ICMPv6,packetInfo.protocol);
        }
    }
    
    if(packetInfo.protocol[0] == 'T' && packetInfo.protocol[1] == 'C' && packetInfo.protocol[2] == 'P'){ // if protocol TCP
        pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
        if (tcpLayer == NULL){
            printf("Something went wrong, couldn't find TCP layer\n");
            return false;
        }
        packetInfo.source_port = (int)ntohs(tcpLayer->getTcpHeader()->portSrc);
        packetInfo.destination_port = (int)ntohs(tcpLayer->getTcpHeader()->portDst);
        string_to_charArray(print_tcp_flags(tcpLayer).c_str(), packetInfo.tcp_flags);
    }
    else if(packetInfo.protocol[0] == 'U' && packetInfo.protocol[1] == 'D' && packetInfo.protocol[2] == 'P'){ // if protocol UDP
        pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
        
        if (udpLayer == NULL){
            printf("Something went wrong, couldn't find UDP layer\n");
            return false;
        }
        
        packetInfo.source_port = (int)ntohs(udpLayer->getUdpHeader()->portSrc); // udp src port.
        packetInfo.destination_port = (int)ntohs(udpLayer->getUdpHeader()->portDst);	// udp dstn port.
    }
    return true;
}
