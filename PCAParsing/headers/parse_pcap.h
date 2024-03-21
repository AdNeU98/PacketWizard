#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#define ipV4TypeCheck 8 
#define ipV6TypeCheck 56710
#define ARPPacketTypeCheck 1544
#define checkforTCP 6
#define checkforUDP 17
#define filetype 101
#define consoletype 202
#include "logging.h" // for logging error/info
#include "session_utilities.h"

using namespace std;

ofstream loggingIn("log_file_pcap_application.txt", ios::out);

// Global variables required to determine protocols, packets size and check IP type. 
int flagToDetermineTCPUDP = 0;
int original_length_of_packet = 0;
int check_IPTYPE = 0;
int print_type_file_or_console; 
int counter_for_duplicate_filename = 1;
string path_of_destination_folder;
fstream storeinCSV;
struct packet_information pckt_info;
session_utilities session_utilObj;


void required_utilities(string path_dst_folder, int type_file_console){
  path_of_destination_folder = path_dst_folder;
  type_file_console = print_type_file_or_console;
}

// Fuction to convert hex to decimal. 
unsigned long hex2dec(string hex)
{
    unsigned long result = 0;
    for (int i=0; i<hex.length(); i++) {
        if (hex[i]>=48 && hex[i]<=57)
        {
            result += (hex[i]-48)*pow(16,hex.length()-i-1);
        } else if (hex[i]>=65 && hex[i]<=70) {
            result += (hex[i]-55)*pow(16,hex.length( )-i-1);
        } else if (hex[i]>=97 && hex[i]<=102) {
            result += (hex[i]-87)*pow(16,hex.length()-i-1);
        }
    }
    return result;
}

// fuction needed to convert decimal to Hexadecimal.
string ConvertDecimaltoHexa(unsigned int value){
    char ss[100];
    sprintf(ss,"%x",value);
    return ss;
}

// function for validation of file - checking the extension.
bool ValidateExtensionOfFile(char filename_of_pcap[]){
    int sizeofile = strlen(filename_of_pcap);
    if(filename_of_pcap[sizeofile-1] == 'p' && filename_of_pcap[sizeofile-2] == 'a' && filename_of_pcap[sizeofile-3] == 'c' && filename_of_pcap[sizeofile-4] =='p' && filename_of_pcap[sizeofile-5] =='.'){
      return true;
    }

    loggingIn<<ERROR<< "File exist incorrect extension.(Not Pcap)" << std::endl;
   return false;
}


set<string> check_for_duplicate_filenames;
string Check_for_duplicate_filename(string csvfile_name){ 

  if(check_for_duplicate_filenames.find(csvfile_name) != check_for_duplicate_filenames.end()){
    csvfile_name.push_back(counter_for_duplicate_filename + '0'); // create unqiue csv name if filename is a duplicate.
    counter_for_duplicate_filename++;
    check_for_duplicate_filenames.insert(csvfile_name);
    return csvfile_name;
  }
  else{
    check_for_duplicate_filenames.insert(csvfile_name); // insert if new_file name for the set. 
  }
  return csvfile_name;
}

void Create_csv_to_store_data (char filename_of_pcap[]){ // create csv according to file names of the pcap file.
  string csvfile_name;
  int iterator_to_parse_the_file = 0;
  for(iterator_to_parse_the_file = 0 ; iterator_to_parse_the_file < (strlen(filename_of_pcap)-5); iterator_to_parse_the_file++){
    csvfile_name.push_back(filename_of_pcap[iterator_to_parse_the_file]);
  }

  csvfile_name = Check_for_duplicate_filename(csvfile_name);  // if file name is duplicate, create a unique csv for that file.
  pckt_info.pcap_filename = csvfile_name;
  pckt_info.destination_folder_path = path_of_destination_folder;
  csvfile_name.push_back('.'); csvfile_name.push_back('c'); csvfile_name.push_back('s'); csvfile_name.push_back('v');
  storeinCSV.open(path_of_destination_folder + csvfile_name, ios::out); 
}

unsigned int convert_ipv4Addr_format(uint8_t arr[]){ // converting the ip address array to 32bit integer using left shift operator.
  return ((arr[3] << 24) | (arr[2] << 16) | ( arr[1] << 8 ) | (arr[0]));
}

// Function for pcap header detail and getting the length of packet. 
void ParsePcapHeaderDetail(FILE *pFile, int Position){
    PackHead P1;
    //cout<<"PacketHeader :"<<endl; // pcap packet header. reading 16 bytes.
    if (fread (&P1, 4, 4, pFile)) {
      original_length_of_packet = P1.orig_len;
      pckt_info.timestamp_sec = P1.ts_sec;
    }
    
}

// Printing Ethernet details like Src MAC and DST MAC. 
void ParseEthernetDetails(FILE *pFile, int Position){
  EthernetHeaderAccessor EHA;
  string helper;
  if(fread(&EHA, sizeof(EHA), 1, pFile)){

      if(print_type_file_or_console == consoletype){
              cout<<"Destination MAC: ";
      }

    for(int i = 0; i<sizeof(EHA.ether_dhost); i++){

      if(i == 5) {
        helper = ConvertDecimaltoHexa((int)EHA.ether_dhost[i]); 
        if(print_type_file_or_console == consoletype){
          cout<<helper; // printing destination MAC
          cout<<endl;
        }
        storeinCSV<<helper<<",";
        break;
      }

      helper = ConvertDecimaltoHexa((int)EHA.ether_dhost[i]);
      if(print_type_file_or_console == consoletype){
         cout<<helper<<":"; //printing destination MAC
      }
      storeinCSV<<helper<<":";
   }

  

    if(print_type_file_or_console == consoletype){
        cout<<"Source MAC: ";
    }

    for(int i = 0; i<sizeof(EHA.ether_shost); i++){

      if(i == 5) {
        helper = ConvertDecimaltoHexa((int)EHA.ether_shost[i]);

        if(print_type_file_or_console == consoletype){
            cout<<helper; // printing source MAC
            cout<<endl;
          } 
        storeinCSV<<helper<<",";
        break;
     }  

      helper = ConvertDecimaltoHexa((int)EHA.ether_shost[i]);
      if(print_type_file_or_console == consoletype){
          cout<<helper<<":"; // printing source MAC
      } 
      storeinCSV<<helper<<":";

   }
    check_IPTYPE  = EHA.ether_type;
  }
  
}



void ParseIPV4HeaderDetails(FILE *pFile, int Position){

  InternetProtocolHeaderAccessor IPV4;
  int pckt_srcIP;
  int pckt_dstIP;

  if(fread(&IPV4,sizeof(IPV4),1,pFile)){

      if((int)IPV4.protocol == checkforUDP){              // determining it's UDP or TCP.
        flagToDetermineTCPUDP = 1;    // 1 means UDP.
        IPV4.protocol = __builtin_bswap16(IPV4.protocol);
      }
      else if((int)IPV4.protocol == checkforTCP){
        flagToDetermineTCPUDP = 0; // 0 means TCP.
      }

      pckt_info.src_ipv4Add = convert_ipv4Addr_format(IPV4.saddr);
      pckt_info.dst_ipv4Add = convert_ipv4Addr_format(IPV4.daddr);


    if(print_type_file_or_console == consoletype){
        cout<<"IP sourceAd: ";
    } 

      for(int i = 0; i<sizeof(IPV4.saddr); i++){
        if(i == 3) {

          if(print_type_file_or_console == consoletype){
              cout<<((int)IPV4.saddr[i]); // printing ipv4 address.
              cout<<endl;
           } 
          storeinCSV<<((int)IPV4.saddr[i])<<",";   
          break;
      }  

      if(print_type_file_or_console == consoletype){
          cout<<((int)IPV4.saddr[i])<<".";
        } 
       storeinCSV<<((int)IPV4.saddr[i])<<".";
     }

      

      if(print_type_file_or_console == consoletype){
          cout<<"IP Destination: ";
        }       
      
      for(int i = 0; i<sizeof(IPV4.daddr); i++){
        if(i == 3) {

          if(print_type_file_or_console == consoletype){
               cout<<((int)IPV4.daddr[i]); // printing ipv4 address.
               cout<<endl;
            }  
           
          storeinCSV<<((int)IPV4.daddr[i])<<",";   
          break;
      }  

      if(print_type_file_or_console == consoletype){
          cout<<((int)IPV4.daddr[i])<<".";
      }
      storeinCSV<<((int)IPV4.daddr[i])<<".";
     }
      
  }
}

// Parsing ARP Header Details.
void ParseARPHeaderDetails(FILE *pFile,int Position){
  ARPHeaderAccess ARP;
  fseek(pFile, Position + 14, SEEK_SET);

  if(print_type_file_or_console == consoletype){
      cout<<"ARP sourceAd: ";
  }
  

  if(fread(&ARP,sizeof(ARP), 1, pFile)){
    for(int i = 0; i<sizeof(ARP.sourceAddressARP); i++){
      if(i == 3) {
  
      if(print_type_file_or_console == consoletype){
          cout<<((int)ARP.sourceAddressARP[i]); // printing ARP address.
        }
        storeinCSV<<((int)ARP.sourceAddressARP[i])<<",";   
        break;
      }  

    if(print_type_file_or_console == consoletype){
      cout<<((int)ARP.sourceAddressARP[i])<<".";
      }
    storeinCSV<<((int)ARP.sourceAddressARP[i])<<".";
    }

    
    if(print_type_file_or_console == consoletype){
          cout<<endl;
          cout<<"ARP Destination: ";
    }
    
    for(int i = 0; i<sizeof(ARP.destinationAddressARP); i++){
      if(i == 3){
        if(print_type_file_or_console == consoletype){
          cout<<((int)ARP.destinationAddressARP[i]); //// printing ARP address.
        }
        storeinCSV<<((int)ARP.destinationAddressARP[i])<<",";   
        break;
        }  

    if(print_type_file_or_console == consoletype){
      cout<<((int)ARP.destinationAddressARP[i])<<".";
    }
    storeinCSV<<((int)ARP.destinationAddressARP[i])<<".";
    }
  }
}

// Parse IPv6 Details. 
void ParseIPV6HeaderDetails(FILE *pFile,int Position){

  fseek(pFile,Position + 8,SEEK_SET);
  InternetProtocol_Ipv6header ipV6;
  
  string result;


  if(fread(&ipV6, sizeof(ipV6), 1, pFile)){

    if(print_type_file_or_console == consoletype){
        cout<<"IPV6 Source Address: ";
    }

    for(int i = 0; i<sizeof(ipV6.sourceaddr);i++){
      if(i == 15){
        result = ConvertDecimaltoHexa((int)ipV6.sourceaddr[i]);
            if(print_type_file_or_console == consoletype){
              cout<<result; //// printing ipv6 address.
              }
        storeinCSV<<result<<",";
        break;
     } 
      
      result = ConvertDecimaltoHexa((int)ipV6.sourceaddr[i]);
      if(print_type_file_or_console == consoletype){
         cout<<result<<":";
      }
      
      storeinCSV<<result<<":";
      if( i == 1) i = i+8;
    }

    if(print_type_file_or_console == consoletype){
      cout<<endl;
      cout<<"IPV6 Destination Address: ";
    }

    for(int i = 0; i<sizeof(ipV6.destinationaddr);i++){
     if(i == 14){ 
      result = ConvertDecimaltoHexa((int)ipV6.destinationaddr[i]);

      if(print_type_file_or_console == consoletype){
         cout<<result; //// printing ipv6 address.
         cout<<endl;
      }
      
      storeinCSV<<result<<",";
      break;
     }

    result = ConvertDecimaltoHexa((int)ipV6.destinationaddr[i]);

    if(print_type_file_or_console == consoletype){
        cout<<result<<":";
    }
    
    storeinCSV<<result<<":";

    if(i == 1) i = i+13;
    }
  }
}

// fucnction for UDP - Source and Dstn port. 
void ParseUDPHeaderDetails(FILE *pFile, int Position){

    fseek(pFile,Position,SEEK_SET);

    UDPHead UD1;

    if (fread (&UD1, 2, 4 , pFile)) {
      if(print_type_file_or_console == consoletype){
        cout<<"UDP sourceport: "<<__builtin_bswap16(UD1.sourcePort)<<endl;
        cout<<"UDP destport: "<<__builtin_bswap16(UD1.destPort)<<endl;
        cout<<endl;
      }
      storeinCSV<<__builtin_bswap16(UD1.sourcePort)<<",";
      storeinCSV<<__builtin_bswap16(UD1.destPort)<<",";
    }

    pckt_info.protocol = "UDP";
    pckt_info.src_port = __builtin_bswap16(UD1.sourcePort);
    pckt_info.dst_port = __builtin_bswap16(UD1.destPort);
    pckt_info.orignal_packet_length = original_length_of_packet;
    pckt_info.tcp_flagInfo = " ";

    session_utilObj.transfer_packet_information(pckt_info);
    
}

// function for TCP Header - source and dest port. 
void ParseTCPHeaderDetails(FILE *pFile, int Position){

    TCPHead TCP_ACCESS;
    
    if (fread (&TCP_ACCESS, sizeof(TCP_ACCESS), 1 , pFile)) {
      if(print_type_file_or_console == consoletype){
        cout<<"TCP sourceport: "<<__builtin_bswap16(TCP_ACCESS.sourcePort)<<endl;
        cout<<"TCP destport: "<<__builtin_bswap16(TCP_ACCESS.destPort)<<endl;
        cout<<endl;
      }
      storeinCSV<<__builtin_bswap16(TCP_ACCESS.sourcePort)<<",";
      storeinCSV<<__builtin_bswap16(TCP_ACCESS.destPort)<<",";
    }

    pckt_info.protocol = "TCP";
    pckt_info.src_port = __builtin_bswap16(TCP_ACCESS.sourcePort);
    pckt_info.dst_port = __builtin_bswap16(TCP_ACCESS.destPort);
    pckt_info.orignal_packet_length = original_length_of_packet;
    pckt_info.tcp_flagInfo = ConvertDecimaltoHexa((int)TCP_ACCESS.tcp_flags);

    if((original_length_of_packet - 66) > 0){
      int string_length = original_length_of_packet-66;
      string store_payload(string_length, '\0');

      if(fread(&store_payload[0], sizeof(char) , (size_t)string_length, pFile)){
        pckt_info.payload = store_payload;
      }
    } else {
      pckt_info.payload  = " ";
    }
    // packet information is sent to session utilities. 
    session_utilObj.transfer_packet_information(pckt_info);
}

// main function where all calls are made. parsing the pcap file. 
void ParsingOfPCAPFile(char filename_of_pcap[]){

    FILE *pFile;
    pFile = fopen (filename_of_pcap,"rb");

     int previousLengthofPackets = 24; // global header included. 
     int iteratorToDeterminePresentLengthOfPacket = 0;
     int determinePacketNumber = 1;
     unsigned int lengthOfWholePacket;

    fseek (pFile , 0 , SEEK_END);
    lengthOfWholePacket = ftell (pFile);
    rewind (pFile);
    
    fseek(pFile,24,SEEK_SET); // skipping the global header.


    while(iteratorToDeterminePresentLengthOfPacket < lengthOfWholePacket){

    storeinCSV<<determinePacketNumber<<",";
    determinePacketNumber++;

    ParsePcapHeaderDetail(pFile,ftell(pFile));

    ParseEthernetDetails(pFile, ftell(pFile));


    if(check_IPTYPE  == ipV4TypeCheck){ // IPV4 Type. 
      ParseIPV4HeaderDetails(pFile,ftell(pFile));
    }
    else if(check_IPTYPE  == ipV6TypeCheck){ // IPV6 Type
      ParseIPV6HeaderDetails(pFile,ftell(pFile));
      goto moveTonextPacket;
    }
    else if(check_IPTYPE  == ARPPacketTypeCheck){ 
      ParseARPHeaderDetails(pFile,ftell(pFile));
      storeinCSV<<",";
      storeinCSV<<",";
      goto moveTonextPacket;
    }
   
    if(flagToDetermineTCPUDP == 1){
    ParseUDPHeaderDetails(pFile,ftell(pFile));
    }
    else if(flagToDetermineTCPUDP == 0){
     ParseTCPHeaderDetails(pFile,ftell(pFile));
    }

    moveTonextPacket:
   // cout<<"Packet length: "<<OriginalLengthOfPacket<<endl;
    storeinCSV<<original_length_of_packet;

    fseek(pFile,previousLengthofPackets + original_length_of_packet + 16,SEEK_SET);

    iteratorToDeterminePresentLengthOfPacket = previousLengthofPackets + original_length_of_packet + 16;

    previousLengthofPackets = iteratorToDeterminePresentLengthOfPacket;

    storeinCSV<<"\n";
    loggingIn<<INFO<< "Complete packet has been read." << std::endl;

    }

    fclose(pFile);
}

