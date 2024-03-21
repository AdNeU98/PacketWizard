#include<iostream>
#include<fstream>
#include<string>
#include<list>
using namespace std;

#define FIN_FLAG "11"
#define SYN_FLAG "2"
#define THRESHOLD_TIME 65

//this will act as a key to uniquely identify a  session in the pcap file
struct session_key {

    uint32_t ipAdd1;
    uint32_t ipAdd2;
    unsigned short int port1;
    unsigned short int port2;
    uint32_t last_seenPkt;
    string protocol;
  
    // sorting the user defined key for the map
   bool operator <(const session_key& sessionObj) const
    {
        if (this->port1 != sessionObj.port1)
        {
            return (this->port1 < sessionObj.port1);
        }

        else if(this->port2 != sessionObj.port2)
        {
            return (this->port2 < sessionObj.port2);
        }

        else if (this->ipAdd1 != sessionObj.ipAdd1)
        {
            return (this->ipAdd1 < sessionObj.ipAdd1);
        }

        else if (this->ipAdd2 != sessionObj.ipAdd2)
        {
            return (this->ipAdd2 < sessionObj.ipAdd2);
        }

        return false;
    }

bool operator == (const session_key& sessionObj) const 
    {
        return (this->port1 == sessionObj.port1 && 
            this->port2 == sessionObj.port2 &&  
            this->ipAdd1 == sessionObj.ipAdd1 && 
            this->ipAdd2 == sessionObj.ipAdd2);  
    }
};

struct packet_information{

    uint32_t src_ipv4Add;
    uint32_t dst_ipv4Add;
    uint32_t timestamp_sec;
    unsigned short int src_port;
    unsigned short int dst_port;
    int orignal_packet_length; 
    string tcp_flagInfo;
    string pcap_filename;
    string protocol;
    string destination_folder_path;
    string payload; 


       bool operator <(const packet_information& pktInfoObj) const
    {
        if (this->src_port!= pktInfoObj.src_port)
        {
            return (this->src_port < pktInfoObj.src_port);
        }

        else if(this->dst_port != pktInfoObj.dst_port)
        {
            return (this->dst_port < pktInfoObj.dst_port);
        }

        else if (this->src_ipv4Add != pktInfoObj.src_ipv4Add)
        {
            return (this->src_ipv4Add < pktInfoObj.src_ipv4Add);
        }

        else if (this->dst_ipv4Add != pktInfoObj.dst_ipv4Add)
        {
            return (this->dst_ipv4Add< pktInfoObj.dst_ipv4Add);
        }

        return false;
    }

    bool operator == (const packet_information& pktInfoObj) const 
    {
        return (this->src_port == pktInfoObj.src_port && 
            this->dst_port == pktInfoObj.dst_port &&  
            this->src_ipv4Add == pktInfoObj.src_ipv4Add && 
            this->dst_ipv4Add == pktInfoObj.dst_ipv4Add);  
    }
};
// global utilities.
list<session_key> last_seenSession_DQ;
map<session_key, list<session_key>::iterator> last_seenSession_map;
map<session_key, map<packet_information, pair<int, int> > > store_sessions; // (int,int) : packet_lenghth, count.


class session_utilities {

    //private :
    //map<>;

public:

    struct packet_information pckt_info;
    struct session_key sessionKey;
    string output_dst_path;
    string pcap_fileName;
    int session_count = 1;
    int payload_pckt_counter = 1;



// removes the session key from map when session is terminatd.
    void delete_session(struct session_key session_KeyVal){
        store_sessions.erase(session_KeyVal);
    }

// printing the information into a text file.
    void print_sessionInfo(struct session_key session_KeyVal){

        if(store_sessions.find(session_KeyVal) != store_sessions.end()){
            ofstream session_file(output_dst_path + pcap_fileName + to_string(session_count) + "_session_file.txt",ios::out);
            session_file<<"IP Addr1"<<" , "<<"IP Addr2"<<" , "<<"Port 1"<<" , "<<"Port 2"<<" , "<<"Bytes"<<" , "<<"Packets"<<" , "<<"Protocol"<<endl;
            session_count++;

            map<packet_information, pair<int, int> > pckt_details;
            map<packet_information, pair<int,int> > :: iterator innerMap_itr;
            pckt_details = store_sessions[session_KeyVal];

            for(innerMap_itr = pckt_details.begin(); innerMap_itr!= pckt_details.end(); innerMap_itr++){
                session_file<<print_ipV4_add(innerMap_itr->first.src_ipv4Add)<<" , ";
                cout<<" ";
                session_file<<print_ipV4_add(innerMap_itr->first.dst_ipv4Add)<<" , ";
                cout<<" ";
                cout<<innerMap_itr->first.src_port<<" ";
                cout<<innerMap_itr->first.dst_port<<" ";
                cout<<innerMap_itr->second.first<<" ";
                cout<<innerMap_itr->second.second<<" "<<endl;

                session_file<<innerMap_itr->first.src_port<<" , ";
                session_file<<innerMap_itr->first.dst_port<<" , ";
                session_file<<innerMap_itr->second.first<<" , ";
                session_file<<innerMap_itr->second.second<<"  ";
                session_file<<innerMap_itr->first.protocol<<endl;
            }
            delete_session(session_KeyVal);
        }
    }

// check for the FIN flag and terminate the session.

    void check_tcpFlag(){
        if(pckt_info.tcp_flagInfo == FIN_FLAG ){
            print_sessionInfo(sessionKey);
        }
    }

// store the sessions with respective packet information, packet count and bytes. 
    void store_session_fields(){
    map<session_key, map<packet_information, pair<int,int> > >  :: iterator outerMap;
    map<packet_information, pair<int,int> > innerMap;
    map<packet_information, pair<int,int> > :: iterator innerMap_itr;

    if(store_sessions.find(sessionKey) == store_sessions.end()){

        if(pckt_info.tcp_flagInfo == SYN_FLAG || pckt_info.tcp_flagInfo == " "){
            store_sessions.insert(make_pair(sessionKey, map<packet_information, pair<int,int> >()));
            store_sessions[sessionKey].insert(make_pair(pckt_info, make_pair(pckt_info.orignal_packet_length, 1)));
        }        
        
    } else if(store_sessions.find(sessionKey)!= store_sessions.end()){

        innerMap = store_sessions[sessionKey];

        if(innerMap.find(pckt_info) == innerMap.end()){
            store_sessions[sessionKey][pckt_info] = make_pair(pckt_info.orignal_packet_length, 1);
            
        } else if(innerMap.find(pckt_info) != innerMap.end()){
            innerMap_itr = store_sessions[sessionKey].find(pckt_info);

            if(innerMap_itr != innerMap.end()){
                
                innerMap_itr->second.first = innerMap_itr->second.first + pckt_info.orignal_packet_length;
            
                innerMap_itr->second.second++;
            }
        }
    }   
}

//check threashold time, if difference between present packet more than 65 seconds, terminate. 
void check_DQ_threshold_time(){

    while(last_seenSession_DQ.size() != 0){

        struct session_key session_KeyValue = last_seenSession_DQ.back();

        if((sessionKey.last_seenPkt -  session_KeyValue.last_seenPkt) < THRESHOLD_TIME){
            break;
        } else if((sessionKey.last_seenPkt - session_KeyValue.last_seenPkt) >= THRESHOLD_TIME){
            last_seenSession_DQ.pop_back();
            last_seenSession_map.erase(session_KeyValue);
            print_sessionInfo(session_KeyValue);
        }
    }
}
// to check if session was already in queue or not. If yes, remove old entry, update the cache. If not, make a new entry.
void last_seen_session(){

    if(last_seenSession_map.find(sessionKey)!=last_seenSession_map.end()){
        last_seenSession_map.erase(sessionKey);
    }

    last_seenSession_DQ.push_front(sessionKey);
    last_seenSession_map[sessionKey] = last_seenSession_DQ.begin();

    check_DQ_threshold_time();

}

// tranfer packet info and check for html content.
void transfer_packet_information(struct packet_information pckt_info){
    this->pckt_info = pckt_info;
    session_key_utilities();
    extract_htmlContent();
}

// constructs the session_key from the packet information values. 
// assigns required values and inititates storing of sessions and check last packet arrival of the session.
void session_key_utilities(){

    if(pckt_info.src_ipv4Add < pckt_info.dst_ipv4Add){
        sessionKey.ipAdd1 = pckt_info.src_ipv4Add;
        sessionKey.ipAdd2 = pckt_info.dst_ipv4Add;
    }else if(pckt_info.src_ipv4Add > pckt_info.dst_ipv4Add){
        sessionKey.ipAdd1 = pckt_info.dst_ipv4Add;
        sessionKey.ipAdd2 = pckt_info.src_ipv4Add;
    }

    if(pckt_info.src_port < pckt_info.dst_port){
        sessionKey.port1 = pckt_info.src_port;
        sessionKey.port2 = pckt_info.dst_port;
    }else if(pckt_info.src_port > pckt_info.dst_port){
        sessionKey.port1 = pckt_info.dst_port;
        sessionKey.port2 = pckt_info.src_port;
    }

    output_dst_path  = pckt_info.destination_folder_path;
    pcap_fileName = pckt_info.pcap_filename;
    sessionKey.last_seenPkt = pckt_info.timestamp_sec;

    store_session_fields();

    if(pckt_info.protocol == "TCP"){ // for tcp session, check for FIN flag.
         check_tcpFlag();
    }

    last_seen_session(); // for TCP and UDP sessions both. TCP if FIN is not available.
}

// using right shift operator extracts values of ip address and prints them.
char * print_ipV4_add(unsigned int part_of_ipv4){                           // using right shift operator to retrieve the values and printing them. 
    char buffer_to_store_ipv4_address[100];       // 0xFF equal to 255 (subnetting).
    unsigned char bytes[4];
    bytes[0] = part_of_ipv4 & 0xFF;
    bytes[1] = (part_of_ipv4 >> 8) & 0xFF;
    bytes[2] = (part_of_ipv4 >> 16) & 0xFF;
    bytes[3] = (part_of_ipv4 >> 24) & 0xFF;   
        
    sprintf(buffer_to_store_ipv4_address ,"%d.%d.%d.%d",bytes[0], bytes[1], bytes[2], bytes[3]);
    printf("%d.%d.%d.%d",bytes[0], bytes[1], bytes[2], bytes[3]);

    return buffer_to_store_ipv4_address;

}

// gets the html content and print it into a file. 
void extract_htmlContent(){
        size_t found = pckt_info.payload.find("<html>");
        if(found != string::npos){
          char store_payload_arry[pckt_info.payload.length() + 1];
          strcpy(store_payload_arry, pckt_info.payload.c_str());

        ofstream print_payload(output_dst_path + pcap_fileName + to_string(session_count) + "_" + to_string(payload_pckt_counter) + "_payload.txt",ios::out);
        payload_pckt_counter++;
          for(int i = found; i<sizeof(store_payload_arry); i++){
            print_payload<<store_payload_arry[i];
        }
    }
}

};

