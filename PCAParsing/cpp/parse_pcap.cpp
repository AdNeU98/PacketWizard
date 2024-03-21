#include <iostream>
using namespace std;


// Function for pcap header detail and getting the length of packet. 
void ParsePcapHeaderDetail(FILE *pFile, int Position){

    PackHead P1;
    if (fread (&P1, 4, 4, pFile)) {
      original_length_of_packet = P1.orig_len;
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

  if(fread(&IPV4,sizeof(IPV4),1,pFile)){

      if((int)IPV4.protocol == checkforUDP){              // determining it's UDP or TCP.
        flagToDetermineTCPUDP = 1;    // 1 means UDP.
        IPV4.protocol = __builtin_bswap16(IPV4.protocol);
      }
      else if((int)IPV4.protocol == checkforTCP){
        flagToDetermineTCPUDP = 0; // 0 means TCP.
        //cout<<"TCP"<<endl;
      }

      conversionofIPV4(IPV4.saddr);  // keeping the count of unique IP Address. 
      conversionofIPV4(IPV4.daddr);

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
  conversionofIPV6(ipV6.sourceaddr); // keeping count of unique ipv6 address.
  conversionofIPV6(ipV6.destinationaddr);
  
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
    
}

// function for TCP Header - source and dest port. 
void ParseTCPHeaderDetails(FILE *pFile, int Position){

    TCPHead TCP_ACCESS;
    
    if (fread (&TCP_ACCESS, 2, 2 , pFile)) {

      if(print_type_file_or_console == consoletype){
        cout<<"TCP sourceport: "<<__builtin_bswap16(TCP_ACCESS.sourcePort)<<endl;
        cout<<"TCP destport: "<<__builtin_bswap16(TCP_ACCESS.destPort)<<endl;
        cout<<endl;
      }
      storeinCSV<<__builtin_bswap16(TCP_ACCESS.sourcePort)<<",";
      storeinCSV<<__builtin_bswap16(TCP_ACCESS.destPort)<<",";
    }
    fseek(pFile,ftell(pFile)+16,SEEK_SET);
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
    storeinCSV<<original_length_of_packet;

    fseek(pFile,previousLengthofPackets + original_length_of_packet + 16,SEEK_SET);

    iteratorToDeterminePresentLengthOfPacket = previousLengthofPackets + original_length_of_packet + 16;

    previousLengthofPackets = iteratorToDeterminePresentLengthOfPacket;

    storeinCSV<<"\n";
    loggingIn<<INFO<< "Complete packet has been read." << std::endl;

    }

    fclose(pFile);
}

