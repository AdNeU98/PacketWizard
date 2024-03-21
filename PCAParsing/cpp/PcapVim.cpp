#include<iostream>
#include<fstream>
#include<sstream>
#include <iomanip>
#include <vector>
#include<string.h>
#include <stdint.h>
#include <stdio.h>
using namespace std;

ofstream myfile ("savedata.txt");
// 24 bytes global header.
//PACKETHEADER.
typedef struct PacketHeader{ // 16 bytes.
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} PackHead;

// ETHERNETHEADER.
typedef struct DESTMAC{
    uint64_t DestMAC :48;
} DNTMAC;

typedef struct SOURCEMAC{
    uint64_t SourceMAC :48;
} SCMAC;

typedef struct EthType{
    uint16_t EtherType;
} EtherT;

typedef struct EthernetHeader{ //14 bytes
    DNTMAC DMAC;
    SCMAC SMAC;
    EtherT ETYPE;
} EthHead;

//IPV4 HEADER. // 20 bytes
typedef struct VerIHL{
    uint16_t VersionIHL : 1;
} VIHL;

typedef struct TYPEservice{
    uint16_t typeService : 1;
} TServ;

typedef struct TotalLength{
    uint16_t totalLength;
    uint16_t identification;
    uint16_t flagFragOffset;
} TotalLen;

typedef struct timetoliveProc{
    uint8_t timetolive;
   // uint8_t protocol : 1;
} TimeProc;

typedef struct Protocol{
   //uint8_t protocol;
    uint16_t protocol: 1;
} Proc;


typedef struct HeadCheckSum{
   uint16_t headerchecksum;
} CheckSum;

typedef struct Address{
    uint32_t sourceAd;
    uint32_t destAd;
} SourceDestAdd;


typedef struct IPV4{ // 20 bytes
    VIHL VL;
    TServ TS;
    TotalLen TL;
    TimeProc TLP;
    Proc PP;
    CheckSum CS;
    SourceDestAdd SDA;
} IpV4;

typedef struct UDPHeader{ // 8 bytes.
    uint16_t sourcePort;
    uint16_t destPort;
    uint16_t length;
    uint16_t checksum;
} UDPHead;

typedef struct TCPHeader{ // 32 bytes but storing only Ports.
    uint16_t sourcePort;
    uint16_t destPort;
 } TCPHead;

int flagToDetermineTCPUDP = 0;
int DetermineLengthOfFileSize = 0;
int OriginalLengthOfPacket = 0;
int CheckIPTYPE = 0;

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

string ConvertDecimaltoHexa(long int value){

    std::stringstream ss;
    ss<< setfill('0') << setw(sizeof(value)*1)<< std::hex << value; // int decimal_value
    std::string res ( ss.str() );
    return res;
}

void printIPVAddress(uint32_t value){

    string result = ConvertDecimaltoHexa(value);
    int iterator = 0;
    while(iterator<result.size()){
       unsigned long val = hex2dec(result.substr(iterator,2));
       cout<<val<<".";
       myfile<<val<<".";
       iterator = iterator + 2;
    }
    //myfile<<endl;
    myfile<<"   ";
}

void printPorts(long int value){

    string result = ConvertDecimaltoHexa(value);
    string new_result = result.substr(0,4);

    unsigned long val = hex2dec(new_result);
    cout<<val<<endl;
    myfile<<val;
    myfile<<"        ";
}

void printIPVLength(int final_from_file){

    long int value = ntohl(final_from_file);
    string result = ConvertDecimaltoHexa(value);
    string new_result = result.substr(0,4);

    if(new_result[3] == '0' && new_result[2] == '0'){ // handling the '0' at starting.. 
        new_result = new_result.substr(0,2);
    }
    else if(new_result[3] == '0'){
        new_result = new_result.substr(0,3);
    }
    unsigned long val = hex2dec(new_result);
    cout<<val<<endl;
}



void ConverterEndianAndPrint(int final_from_file){
      printPorts(ntohl(final_from_file));
}

void ConvertMacAddress(long int value_from_file){

    string result = ConvertDecimaltoHexa(value_from_file);
    result = result.substr(0,12);

    int iterator = 0;
    while(iterator<result.size()){
       cout<<(result.substr(iterator,2))<<":";
       myfile <<(result.substr(iterator,2))<<":";
       iterator = iterator + 2;
    }
    cout<<endl;
    myfile<<"   ";
}

void PrintPcapHeaderDetail(FILE *pFile, int Position){

    PackHead P1;
    cout<<"PacketHeader :"<<endl; // pcap packet header. reading 16 bytes.
    if (fread (&P1, 4, 4, pFile)) {
      cout<<"orig_len :"<<P1.orig_len<<endl;
      OriginalLengthOfPacket = P1.orig_len;
    }
    cout<<endl;

}


void PrintEthernetDetails(FILE *pFile, int Position){

    EthHead E1;
    cout<<"EThernetHeader :"<<endl;
    if (fread (&E1.DMAC, 6, 1 , pFile)) {
      cout<<"DestMAC : ";
      ConvertMacAddress(__builtin_bswap64(E1.DMAC.DestMAC));
    }

    if (fread (&E1.SMAC, 6, 1 , pFile)) {
      cout<<"SourceMAC : ";
      ConvertMacAddress(__builtin_bswap64(E1.SMAC.SourceMAC));
    }

    if (fread (&E1.ETYPE, 2, 1 , pFile)) {
      cout<<"EtherType:"<<E1.ETYPE.EtherType<<endl;
      CheckIPTYPE = E1.ETYPE.EtherType;

    }

    cout<<endl;

}

void PrintIPVHeaderDetails(FILE *pFile, int Position){

    IpV4 IP;

    cout<<"IP Header"<<endl;
    if (fread (&IP.VL, 1, 1 , pFile)) {
        cout<<"IPVType: ";
     if(__builtin_bswap16(IP.VL.VersionIHL) == 256){
        cout<<"4"<<endl;
      }
    }

    if (fread (&IP.TS, 1, 1 , pFile)) {
      cout<<"IP typeService: "<<IP.TS.typeService<<endl;
    }

    if (fread (&IP.TL, 2, 3 , pFile)) {
      cout<<"IP totalLength: ";
      printIPVLength(IP.TL.totalLength);
      cout<<"IP identification: "<<IP.TL.identification<<endl;
      cout<<"flagFragOffset: "<<IP.TL.flagFragOffset<<endl;
    }

    if (fread (&IP.TLP, 1, 1 , pFile)) {
      cout<<"IP timetolive: "<<IP.TLP.timetolive<<endl;
      cout<<"IP protocol: "<<IP.TLP.protocol<<endl;
    }

    if (fread (&IP.PP, 1, 1 , pFile)) {
      cout<<"IP protocol: ";
      if(__builtin_bswap16(IP.PP.protocol) == 256){
        flagToDetermineTCPUDP = 1;
        IP.PP.protocol = __builtin_bswap16(IP.PP.protocol);
        cout<<"UDP"<<endl;
      }
      else if(__builtin_bswap16(IP.PP.protocol) == 0){
        flagToDetermineTCPUDP = 0;
        IP.PP.protocol = __builtin_bswap16(IP.PP.protocol);
        cout<<"TCP"<<endl;
      }
    }




    if (fread (&IP.CS, 2, 1 , pFile)) {
     cout<<"IP headerchecksum: "<<IP.CS.headerchecksum<<endl;
    }

    if (fread (&IP.SDA, 4, 2 , pFile)) {
      cout<<"IP sourceAd: ";
      IP.SDA.sourceAd = ntohl(IP.SDA.sourceAd);
      printIPVAddress(IP.SDA.sourceAd); cout<<endl;
      cout<<"IP destAd: ";
      IP.SDA.destAd = ntohl(IP.SDA.destAd);
      printIPVAddress(IP.SDA.destAd);
      cout<<endl;
    }

    cout<<endl;

}

void PrintUDPHeaderDetails(FILE *pFile, int Position){

    fseek(pFile,Position,SEEK_SET);

    UDPHead UD1;
    cout<<"UDPHeader: "<<endl;

    if (fread (&UD1, 2, 4 , pFile)) {
      cout<<"UDP sourceport: ";
      ConverterEndianAndPrint(UD1.sourcePort);
      cout<<"UDP destport: ";
      ConverterEndianAndPrint(UD1.destPort);
    }
    cout<<endl;
}

void PrintTCPHeaderDetails(FILE *pFile, int Position){
    TCPHead TCP_ACCESS;
    cout<<"TCP Header: "<<endl;

    if (fread (&TCP_ACCESS, 2, 2 , pFile)) {
      cout<<"TCP sourceport: ";
      ConverterEndianAndPrint(TCP_ACCESS.sourcePort);

      cout<<"TCP destport: ";
      ConverterEndianAndPrint(TCP_ACCESS.destPort);
    }
    fseek(pFile,ftell(pFile)+16,SEEK_SET);
    cout<<endl;
}



int main()
{   
    FILE *pFile;

    pFile = fopen ("SinglePacket.pcap", "rb");

    long long int previousLengthofPackets = 24; // global header included. 
    long long int lengthOfWholePacket;
    long long int iteratorToDeterminePresentLengthOfPacket = 0;
    long long int DeterminePacketNumber = 1;
    fseek (pFile , 0 , SEEK_END);
    lengthOfWholePacket = ftell (pFile);
    cout<<"lengthOfWholePacket : "<<lengthOfWholePacket<<endl;
    rewind (pFile);
    
    fseek(pFile,24,SEEK_SET); // skipping the global header.

    myfile<<"S.NO    DstMAC              SrcMAC              SrcIP          DstIP          SrcPort     DstPort       LengthOfPacket"<<endl;

    while(iteratorToDeterminePresentLengthOfPacket<lengthOfWholePacket){

    cout<<"Details of Packet Number: "<<DeterminePacketNumber<<endl;
    myfile <<DeterminePacketNumber<<"   ";
    DeterminePacketNumber++;

    PrintPcapHeaderDetail(pFile,ftell(pFile));

    PrintEthernetDetails(pFile,ftell(pFile));

    if(CheckIPTYPE == 8){
      PrintIPVHeaderDetails(pFile,ftell(pFile));
    }
   
    if(flagToDetermineTCPUDP == 1){
    PrintUDPHeaderDetails(pFile,ftell(pFile));
    }
    else if(flagToDetermineTCPUDP == 0){
     PrintTCPHeaderDetails(pFile,ftell(pFile));
    }
    cout<<"Packet length: "<<OriginalLengthOfPacket<<endl;
    myfile<<"      "<<OriginalLengthOfPacket;
    fseek(pFile,previousLengthofPackets+OriginalLengthOfPacket + 16,SEEK_SET);

    iteratorToDeterminePresentLengthOfPacket = previousLengthofPackets+OriginalLengthOfPacket+16;

    previousLengthofPackets = iteratorToDeterminePresentLengthOfPacket;

    myfile<<endl;
    }

    fclose(pFile);

    return 0;
}
