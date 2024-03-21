#include<iostream>
#include<fstream>
#include<string.h>
#include<map>
#include<unordered_map>
using namespace std;

typedef struct IPV6_count_storage { // to store 16 bytes of ipv6 address.
  uint32_t part1_of_ipv6_address;	// divided them into 4 parts, 4 bytes each.
  uint32_t part2_of_ipv6_address;
  uint32_t part3_of_ipv6_address;
  uint32_t part4_of_ipv6_address;
} store_ipv6_address_count;

//ofstream storeUniqueIPAddress("IPAddressData.csv", ios::out);
fstream storeUniqueIPAddress;
unordered_map<uint32_t,int> map_storing_count_of_unq_ipV4_address; // storing ipv4 address
map<store_ipv6_address_count, int> map_for_storing_ipv6_count;	// storing ipv6 address. 

void csv_for_count_of_IP_Address(string destination_folder){
	storeUniqueIPAddress.open(destination_folder + "count_IP_address.csv", ios::out);
}

void countofunqiue_IPV4_address(unsigned int keyValueForMap){ // storing unqiue ipv4 address if not present in map, else create key.

  if(map_storing_count_of_unq_ipV4_address.find(keyValueForMap) != map_storing_count_of_unq_ipV4_address.end()){
    map_storing_count_of_unq_ipV4_address[keyValueForMap]++;
  }
  else{
    map_storing_count_of_unq_ipV4_address[keyValueForMap] = 1;
  }
}

void print_ipV4_address(unsigned int part_of_ipv4)
{							// using right shift operator to retrieve the values and printing them. 
	  char buffer_to_store_ipv4_address[100];		// 0xFF equal to 255 (subnetting).
    unsigned char bytes[4];
    bytes[0] = part_of_ipv4 & 0xFF;
    bytes[1] = (part_of_ipv4 >> 8) & 0xFF;
    bytes[2] = (part_of_ipv4 >> 16) & 0xFF;
    bytes[3] = (part_of_ipv4 >> 24) & 0xFF;   
        
    sprintf(buffer_to_store_ipv4_address ,"%d.%d.%d.%d",bytes[0], bytes[1], bytes[2], bytes[3]);
    storeUniqueIPAddress<<buffer_to_store_ipv4_address<<",";
}

void unique_ipv4_address_count(){
  // Get an iterator pointing to begining of map
  unordered_map<uint32_t, int>::iterator it = map_storing_count_of_unq_ipV4_address.begin();

// Iterate over the map using iterator
  while(it != map_storing_count_of_unq_ipV4_address.end())
  { 
    print_ipV4_address(it->first);
    storeUniqueIPAddress<<it->second<<"\n";
    it++;
  }
}

void conversionofIPV4(uint8_t arr[]){ // converting the ip address array to 32bit integer using left shift operator.
  countofunqiue_IPV4_address((arr[3] << 24) | (arr[2] << 16) | ( arr[1] << 8 ) | (arr[0]));
}

void print_ipV6_Address(unsigned int part_of_ipv6, int count)
{  // retriving the values of ipv6 address, function called 4 times for a single address. 
	// 16 bytes are divided into 4 bytes each. 

    uint32_t bytes[4];
    char buffer_to_store_ipv6_address[100];
    bytes[0] = part_of_ipv6 & 0xFF;
    bytes[1] = (part_of_ipv6 >> 8) & 0xFF;
    bytes[2] = (part_of_ipv6 >> 16) & 0xFF;
    bytes[3] = (part_of_ipv6 >> 24) & 0xFF;  

    if(count == 4){       
    	sprintf(buffer_to_store_ipv6_address ,"%x%x:%x%x",bytes[0], bytes[1], bytes[2], bytes[3]);
    	storeUniqueIPAddress<<buffer_to_store_ipv6_address;
    	return;
    }

    //printf("%x%x:%x%x:", bytes[0], bytes[1], bytes[2], bytes[3]);        
    sprintf(buffer_to_store_ipv6_address ,"%x%x:%x%x:",bytes[0], bytes[1], bytes[2], bytes[3]);
    storeUniqueIPAddress<<buffer_to_store_ipv6_address;  
}

bool operator<(const store_ipv6_address_count& compare_ip1, const store_ipv6_address_count& compare_ip2) {

	if(compare_ip1.part4_of_ipv6_address != compare_ip2.part4_of_ipv6_address){
		return (compare_ip1.part4_of_ipv6_address < compare_ip2.part4_of_ipv6_address);
	}
	else if(compare_ip1.part3_of_ipv6_address != compare_ip2.part3_of_ipv6_address){
		return (compare_ip1.part3_of_ipv6_address < compare_ip2.part3_of_ipv6_address);
	}
	else if(compare_ip1.part2_of_ipv6_address != compare_ip2.part2_of_ipv6_address){
		return (compare_ip1.part2_of_ipv6_address < compare_ip2.part2_of_ipv6_address);
	}
	else{
		return (compare_ip1.part1_of_ipv6_address < compare_ip2.part1_of_ipv6_address);
	}
}

void conversionofIPV6(uint8_t ipv6_address_from_main[]) {
	// dividing the ipv6 16 byte address into 4 -> 4 byte integer values using left shift operator.
  // putting them into the map and increasing the count if they exist.
  store_ipv6_address_count ipv6;
  ipv6.part1_of_ipv6_address = (ipv6_address_from_main[3] << 24) | (ipv6_address_from_main[2] << 16) | ( ipv6_address_from_main[1] << 8 ) | (ipv6_address_from_main[0]);
  ipv6.part2_of_ipv6_address = (ipv6_address_from_main[7] << 24) | (ipv6_address_from_main[6] << 16) | ( ipv6_address_from_main[5] << 8 ) | (ipv6_address_from_main[4]);
  ipv6.part3_of_ipv6_address = (ipv6_address_from_main[11] << 24) | (ipv6_address_from_main[10] << 16) | ( ipv6_address_from_main[9] << 8 ) | (ipv6_address_from_main[8]);
  ipv6.part4_of_ipv6_address = (ipv6_address_from_main[15] << 24) | (ipv6_address_from_main[14] << 16) | ( ipv6_address_from_main[13] << 8 ) | (ipv6_address_from_main[12]);
  map_for_storing_ipv6_count[ipv6]++;
}


void unique_ipv6_address_count(){
    map<store_ipv6_address_count,int>:: iterator itr;
    // iterating the map for ipv6 address, sending 4 parts for single adddress.
    // and printing the count.
  for(itr = map_for_storing_ipv6_count.begin();itr!= map_for_storing_ipv6_count.end();itr++){
      print_ipV6_Address(itr->first.part1_of_ipv6_address, 1);
      print_ipV6_Address(itr->first.part2_of_ipv6_address, 2);
      print_ipV6_Address(itr->first.part3_of_ipv6_address, 3);
      print_ipV6_Address(itr->first.part4_of_ipv6_address, 4);
      storeUniqueIPAddress<<","<<itr->second<<"\n";
      //cout<<"::"<<itr->second<<endl;
  }
}
