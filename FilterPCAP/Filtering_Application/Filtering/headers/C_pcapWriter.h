#include <string>
#include <stdint.h>
#include <fstream>

#define FILELIMIT 500000000
using namespace std;

class C_pcapWriter{
    private :
    string output_file_name;
    fstream output_pcap_file;
    string output_dir;
    char *global_header;
    int count_file_number = 0;
public:
    void openOutputDirectory(string output_directory);
    // open directory
    
    void writeGlobalHeader(char*global_hdr);
    // writes global header
    
    void output_dump(char*packet_header, int payload_len, char*payload);
    // Accepts packet information including the global header, packet header and rest of the payload, and write that in a target output_dump.pcap file
    
    string pcapWriter_intToString(int count_file_number);
    
    void closeOutputDirectory();
    // close Directory
};

