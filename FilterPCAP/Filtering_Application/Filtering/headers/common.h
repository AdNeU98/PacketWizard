#ifndef  COMMON_H 
#define COMMON_H

#include <stdint.h>
#include <cstdint>
#include <vector>
#include <cstring>
#include <climits>

using namespace std;

#define SIZE_GLOBAL_HEADER 24
#define SIZE_PACKET_HEADER 16
#define MAX_PACKET_SIZE_ALLOWED 1600

// Structure required for input directory, output directory and filterString information
typedef struct ST_UserInputs{
    string inputDir, outputDir, filterStr;
} st_userinputs;

// Packet Header structure
typedef struct ST_packet_hdr {
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} ST_PacketHeader;

// Global packet  header class
class C_packet_information{
public:
    int packet_length ;
    char source_macAddress[20];
    char destination_macAddress[20];
    uint16_t ethernet_type;
    char source_ipAddress[20];
    char destination_ipAddress[20];
    char protocol[10];
    uint16_t source_port;
    uint16_t destination_port;
    char tcp_flags[20];
    
    void reset(){
        packet_length = 0;
        memset(&source_macAddress[0], 0, sizeof(source_macAddress));
        memset(&destination_macAddress[0], 0, sizeof(destination_macAddress));
        ethernet_type = 0;
        memset(&source_ipAddress[0], 0, sizeof(source_ipAddress));
        memset(&destination_ipAddress[0], 0, sizeof(destination_ipAddress));
        memset(&protocol[0], 0, sizeof(protocol));
        source_port =0;
        destination_port =0 ;
        memset(&tcp_flags[0], 0, sizeof(tcp_flags));
    }
    
    // constructor
    C_packet_information(){
        reset();
    }
};

struct st_filter_tokens{
    char filter_tokens[50];
};

// Extracting all the discrete filters from filter string by dissecting it, and send it to filtering module
struct ST_filterDependencies{
    vector<vector<st_filter_tokens> > filterVector;
    vector<int> pos;
    string boolFilter;
};

#endif


