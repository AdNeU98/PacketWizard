#include<iostream>
#include<fstream>
#include<string.h>
#include <dirent.h>
#include<pthread.h>
 
#include "headers/logging.h"
#include "headers/ParsePcap.h"
#include "headers/findUniqueIP.h"

#define ipV4TypeCheck 8 
#define ipV6TypeCheck 56710
#define ARPPacketTypeCheck 1544
#define checkforTCP 6
#define checkforUDP 17
#define filetype 101
#define consoletype 202
using namespace std;
  
ofstream storeinCSV("savedata.csv", ios::out);
ofstream loggingIn("mylogfile.txt",ios::out);

// Global variables required to determine protocols, packets size and check IP type. 
int flagToDetermineTCPUDP = 0;
int DetermineLengthOfFileSize = 0;
int OriginalLengthOfPacket = 0;
int CheckIPTYPE = 0;
int PrintType_FileOrConsole; 
char path[1000];
 

// Fuction to conver hex to decimal. 

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

// Function for pcap header detail and getting the length of packet. 

void ParsePcapHeaderDetail(FILE *pFile, int Position){

    PackHead P1;
    if (fread (&P1, 4, 4, pFile)) {
      OriginalLengthOfPacket = P1.orig_len;
      cout<<endl;
    }
    
}

// Printing Ethernet details like Src MAC and DST MAC. 
void ParseEthernetDetails(FILE *pFile, int Position){
  EthernetHeaderAccessor EHA;
  string helper;
  if(fread(&EHA, sizeof(EHA), 1, pFile)){

      if(PrintType_FileOrConsole == consoletype){
              cout<<"Destination MAC: ";
      }

    for(int i = 0; i<sizeof(EHA.ether_dhost); i++){

      if(i == 5) {
        helper = ConvertDecimaltoHexa((int)EHA.ether_dhost[i]); 
        if(PrintType_FileOrConsole == consoletype){
          cout<<helper;
          cout<<endl;
        }
        storeinCSV<<helper<<",";
        break;
      }

      helper = ConvertDecimaltoHexa((int)EHA.ether_dhost[i]);
      if(PrintType_FileOrConsole == consoletype){
         cout<<helper<<":";
      }
      storeinCSV<<helper<<":";
   }

  

    if(PrintType_FileOrConsole == consoletype){
        cout<<"Source MAC: ";
    }

    for(int i = 0; i<sizeof(EHA.ether_shost); i++){

      if(i == 5) {
        helper = ConvertDecimaltoHexa((int)EHA.ether_shost[i]);

        if(PrintType_FileOrConsole == consoletype){
            cout<<helper;
            cout<<endl;
          } 
        storeinCSV<<helper<<",";
        break;
     }  

      helper = ConvertDecimaltoHexa((int)EHA.ether_shost[i]);
      if(PrintType_FileOrConsole == consoletype){
          cout<<helper<<":";
      } 
      storeinCSV<<helper<<":";

   }
    CheckIPTYPE = EHA.ether_type;
  }
  
}


void ParseIPV4HeaderDetails(FILE *pFile, int Position){

  InternetProtocolHeaderAccessor IPV4;

  if(fread(&IPV4,sizeof(IPV4),1,pFile)){
      if((int)IPV4.protocol == checkforUDP){
        flagToDetermineTCPUDP = 1;    // 1 means UDP.
        IPV4.protocol = __builtin_bswap16(IPV4.protocol);
      }
      else if((int)IPV4.protocol == checkforTCP){
        flagToDetermineTCPUDP = 0; // 0 means TCP.
      }

      conversionofIPV4(IPV4.saddr);
      conversionofIPV4(IPV4.daddr);

    if(PrintType_FileOrConsole == consoletype){
        cout<<"IP sourceAd: ";
    } 

      for(int i = 0; i<sizeof(IPV4.saddr); i++){
        if(i == 3) {

          if(PrintType_FileOrConsole == consoletype){
              cout<<((int)IPV4.saddr[i]);
              cout<<endl;
           } 
          storeinCSV<<((int)IPV4.saddr[i])<<",";   
          break;
      }  

      if(PrintType_FileOrConsole == consoletype){
          cout<<((int)IPV4.saddr[i])<<".";
        } 
       storeinCSV<<((int)IPV4.saddr[i])<<".";
     }

      

      if(PrintType_FileOrConsole == consoletype){
          cout<<"IP Destination: ";
        }       
      
      for(int i = 0; i<sizeof(IPV4.daddr); i++){
        if(i == 3) {

          if(PrintType_FileOrConsole == consoletype){
               cout<<((int)IPV4.daddr[i]);
               cout<<endl;
            }  
           
          storeinCSV<<((int)IPV4.daddr[i])<<",";   
          break;
      }  

      if(PrintType_FileOrConsole == consoletype){
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

  if(PrintType_FileOrConsole == consoletype){
      cout<<"ARP sourceAd: ";
  }
  

  if(fread(&ARP,sizeof(ARP), 1, pFile)){
    for(int i = 0; i<sizeof(ARP.sourceAddressARP); i++){
      if(i == 3) {
  
      if(PrintType_FileOrConsole == consoletype){
          cout<<((int)ARP.sourceAddressARP[i]); 
        }
        storeinCSV<<((int)ARP.sourceAddressARP[i])<<",";   
        break;
      }  

    if(PrintType_FileOrConsole == consoletype){
      cout<<((int)ARP.sourceAddressARP[i])<<".";
      }
    storeinCSV<<((int)ARP.sourceAddressARP[i])<<".";
    }

    
    if(PrintType_FileOrConsole == consoletype){
          cout<<endl;
          cout<<"ARP Destination: ";
    }
    
    for(int i = 0; i<sizeof(ARP.destinationAddressARP); i++){
      if(i == 3){
        if(PrintType_FileOrConsole == consoletype){
          cout<<((int)ARP.destinationAddressARP[i]);
        }
        storeinCSV<<((int)ARP.destinationAddressARP[i])<<",";   
        break;
        }  

    if(PrintType_FileOrConsole == consoletype){
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

    if(PrintType_FileOrConsole == consoletype){
        cout<<"IPV6 Source Address: ";
    }

    for(int i = 0; i<sizeof(ipV6.sourceaddr);i++){
      if(i == 15){
        result = ConvertDecimaltoHexa((int)ipV6.sourceaddr[i]);
            if(PrintType_FileOrConsole == consoletype){
              cout<<result;
              }
        storeinCSV<<result<<",";
        break;
     } 
      
      result = ConvertDecimaltoHexa((int)ipV6.sourceaddr[i]);
      if(PrintType_FileOrConsole == consoletype){
         cout<<result<<":";
      }
      
      storeinCSV<<result<<":";
      if( i == 1) i = i+8;
    }

    if(PrintType_FileOrConsole == consoletype){
      cout<<endl;
      cout<<"IPV6 Destination Address: ";
    }

    for(int i = 0; i<sizeof(ipV6.destinationaddr);i++){
     if(i == 14){ 
      result = ConvertDecimaltoHexa((int)ipV6.destinationaddr[i]);

      if(PrintType_FileOrConsole == consoletype){
         cout<<result;
         cout<<endl;
      }
      
      storeinCSV<<result<<",";
      break;
     }

    result = ConvertDecimaltoHexa((int)ipV6.destinationaddr[i]);

    if(PrintType_FileOrConsole == consoletype){
        cout<<result<<":";
    }
    
    storeinCSV<<result<<":";

    if(i == 1) i = i+13;
    }
  }
  conversionofIPV6(ipV6.sourceaddr);
  conversionofIPV6(ipV6.destinationaddr);

    
}

// fucnction for UDP - Source and Dstn port. 
void ParseUDPHeaderDetails(FILE *pFile, int Position){

    fseek(pFile,Position,SEEK_SET);

    UDPHead UD1;

    if (fread (&UD1, 2, 4 , pFile)) {
      if(PrintType_FileOrConsole == consoletype){
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
    //cout<<"TCP Header: "<<endl;

    if (fread (&TCP_ACCESS, 2, 2 , pFile)) {

      if(PrintType_FileOrConsole == consoletype){
        cout<<"TCP sourceport: "<<__builtin_bswap16(TCP_ACCESS.sourcePort)<<endl;
        cout<<"TCP destport: "<<__builtin_bswap16(TCP_ACCESS.destPort)<<endl;
        cout<<endl;
      }
      storeinCSV<<__builtin_bswap16(TCP_ACCESS.sourcePort)<<",";
      storeinCSV<<__builtin_bswap16(TCP_ACCESS.destPort)<<",";
    }
    fseek(pFile,ftell(pFile)+16,SEEK_SET);
    
}

int findlength_of_filename(char filename[]){

  int iterating_theFile = 0;
  while(filename[iterating_theFile]){
    iterating_theFile++;
  }
  return iterating_theFile;
}

// function for validation of file - checking the extension.
bool ValidateExtensionOfFile(char filename[]){
    int sizeofile = findlength_of_filename(filename);
    if(filename[sizeofile-1] == 'p' && filename[sizeofile-2] == 'a' && filename[sizeofile-3] == 'c' && filename[sizeofile-4] =='p' && filename[sizeofile-5] =='.'){
      return true;
    }

  loggingIn<<ERROR<< "File exist incorrect extension.(Not Pcap)" << std::endl;
   return false;
}

// main function where all calls are made. parsing the pcap file. 
void ParsingOfPCAPFile(char filename[]){

    FILE *pFile;
    pFile = fopen (filename,"rb");

    long long int previousLengthofPackets = 24; // global header included. 
    long long int lengthOfWholePacket;
    long long int iteratorToDeterminePresentLengthOfPacket = 0;
    long long int determinePacketNumber = 1;

    fseek (pFile , 0 , SEEK_END);
    lengthOfWholePacket = ftell (pFile);
    cout<<"lengthOfWholePacket : "<<lengthOfWholePacket<<endl;
    rewind (pFile);
    
    fseek(pFile,24,SEEK_SET); // skipping the global header.


    while(iteratorToDeterminePresentLengthOfPacket<lengthOfWholePacket){

    cout<<"Details of Packet Number: "<<determinePacketNumber<<endl;
    storeinCSV<<determinePacketNumber<<",";
    determinePacketNumber++;

    ParsePcapHeaderDetail(pFile,ftell(pFile));

    ParseEthernetDetails(pFile, ftell(pFile));


    if(CheckIPTYPE == ipV4TypeCheck){ // IPV4 Type. 
      ParseIPV4HeaderDetails(pFile,ftell(pFile));
    }
    else if(CheckIPTYPE == ipV6TypeCheck){ // IPV6 Type
      ParseIPV6HeaderDetails(pFile,ftell(pFile));
      goto moveTonextPacket;
    }
    else if(CheckIPTYPE == ARPPacketTypeCheck){ 
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
    cout<<"Packet length: "<<OriginalLengthOfPacket<<endl;
    storeinCSV<<OriginalLengthOfPacket;

    fseek(pFile,previousLengthofPackets+OriginalLengthOfPacket + 16,SEEK_SET);

    iteratorToDeterminePresentLengthOfPacket = previousLengthofPackets + OriginalLengthOfPacket+16;

    previousLengthofPackets = iteratorToDeterminePresentLengthOfPacket;

    storeinCSV<<"\n";
    loggingIn<<INFO<< "Complete packet has been read." << std::endl;

    }

    fclose(pFile);

}

bool check_directory_exists(){

  struct dirent *entry;
  DIR *dir = opendir(path);
  if (dir == NULL) {
      cout<<"Directory does not exist which the user has provided.";
      return false;   
  }
  closedir(dir); 
  return true;
}

void* Watching_over_Folder(void *arg){

      struct dirent *entry;
      char filename[256];
      char *quit_t = (char *) arg;
      pthread_detach(pthread_self());

      while(true){

        DIR *dir = opendir(path);

        while ((entry = readdir(dir)) != NULL) {
          string helper = entry->d_name;
         if(helper == "." || helper == ".." || helper == ".DS_Store"){
          continue;
        }
        sprintf(filename,"%s/%s",path,entry->d_name);

      std::ifstream fileCheck(filename, ios_base::binary);
   
      if(fileCheck && ValidateExtensionOfFile(filename)){ // check extension and existence. 

      cout<<"File opened"<<endl;  
      storeinCSV<<"S.No"<<","<<"DstMAC"<<","<<"SrcMAC"<<","<<"SrcAd"<<","<<"DstAd"<<","<<"SrcPort"<<","<<"DstPort"<<","<<"PacketLength"<<"\n";
      loggingIn<<INFO<< "File opened successfully." << std::endl;

      if(PrintType_FileOrConsole == filetype || PrintType_FileOrConsole == consoletype){
        ParsingOfPCAPFile(filename); 
        cout<<endl;
        cout<<"Count of Unqiue IP Addresses."<<endl;
        iterate_map_IPV4();
        print_mapIPV6();
        cout<<"Data is saved successfully in savedata.csv filename";
        loggingIn<<INFO<<"Complete file has been read and closed." << std::endl;

        if (remove(filename)== 0) {
          printf("Deleted successfully"); 
       }
      }
    }
    else{
        cout<<"File does not exist or the extension of the file is not PCAP.";
        loggingIn<<INFO<< "File does not exist/incorrect extension." <<endl;
    }

    }
    closedir(dir);
    if(*quit_t == 'q'){
      pthread_exit(NULL); 
    } 
  }

}

void Initilise_ParsingPcapFile(){

    pthread_t pthread_id;
    char val = '\0';
    pthread_create(&pthread_id, NULL, &Watching_over_Folder,(void*)&val);; 
    while(val != 'q'){
        cin>>val;
    }
    pthread_exit(NULL);
}


int main()
{   
    cout<<"Press, 'q' to exit the application."<<endl;
    cout<<"Path of folder which needs to be watched: ";
    cin>>path;

    if(check_directory_exists() == false){
      return 0;
    }

    cout<<"Press 101, if you wish to print in the file."<<endl;
    cout<<"Press 202, if you wish to print on the console."<<endl;
    cout<<"Enter the choice: ";
    cin>>PrintType_FileOrConsole;

    if(PrintType_FileOrConsole == filetype || PrintType_FileOrConsole == consoletype){
      Initilise_ParsingPcapFile();
    }
    else{
          cout<<"Wrong choice selected."<<endl;
    }
    
    return 0;
}