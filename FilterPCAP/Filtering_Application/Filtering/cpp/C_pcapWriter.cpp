#include "headers/C_pcapWriter.h"
#include <string>
#include <fstream>
#include <iostream>
using namespace std;

#define SIZE_GLOBAL_HEADER 24
#define SIZE_PACKET_HEADER 16
#define MAX_PACKET_SIZE_ALLOWED 1600

string C_pcapWriter::pcapWriter_intToString(int count_file_number){
    char buffer[6];
    sprintf(buffer,"%d", count_file_number);
    return buffer;
}

// writes global header
void C_pcapWriter::writeGlobalHeader(char*global_hdr){
    global_header = global_hdr;
    output_pcap_file.write(global_hdr, SIZE_GLOBAL_HEADER);
}

// open directory
void C_pcapWriter::openOutputDirectory(string output_directory){
    output_dir = output_directory;
    output_file_name = output_directory + "/output_dump_" + pcapWriter_intToString(count_file_number) + ".pcap";
    output_pcap_file.open(output_file_name.c_str(), ios::out | ios::app | ios::binary);
}

// Accepts packet information including the global header, packet header and rest of the payload, and write that in a target output_dump.pcap file
void C_pcapWriter::output_dump(char*packet_header, int payload_len, char*payload){
    if(output_pcap_file.is_open()){
        output_pcap_file.write(packet_header, SIZE_PACKET_HEADER);
        output_pcap_file.write(payload, payload_len);
    }
    
    int writer_fileSize = output_pcap_file.tellp();
    
    if( writer_fileSize > FILELIMIT){
        closeOutputDirectory();
        count_file_number++;
        openOutputDirectory(output_dir);
        writeGlobalHeader(global_header);
    }
} 

// close Directory
void C_pcapWriter::closeOutputDirectory(){
    output_pcap_file.close();
}
