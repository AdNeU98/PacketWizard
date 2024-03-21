#include <stdlib.h>
#include <sys/time.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <string.h>
#include "pcapplusplus_headers.h"
#include "common.h"

#define IPv4_Type 2048
#define IPv6_Type 34525
#define ARP_Type  2054
#define ICMPv6_Type 16777216

using namespace std;

class C_packetParser{
public:
    bool single_packet_parser(uint8_t* PayL, int packet_length, timeval timestamp, C_packet_information &packetInfo);
    // all packet info will be stored in packetInfo.
    
    string get_protocol(pcpp::ProtocolType protocolType);
    // To extract the protocol type of any layer.
    
    void string_to_charArray(string str, char cArr[]);
    // information which is returned as string are stored in character array here.
    
    string print_tcp_flags(pcpp::TcpLayer* tcpLayer);
    // TCP flags information.
};
