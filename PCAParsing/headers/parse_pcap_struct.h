
// skipping the 24 global header.

#define ETH_ALEN 6  /* Octets in one ethernet addr   */

typedef struct PacketHeader { // Packet header - 16 bytes. 
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
} PackHead;

// Ethernet Header Structure : 14 Bytes. 
typedef struct EthernetHeaderStructure {
    uint8_t  ether_dhost[ETH_ALEN];        /* destination eth addr        */
    uint8_t  ether_shost[ETH_ALEN];        /* source ether addr        */
    uint16_t ether_type;  
} EthernetHeaderAccessor;

// IPHeader Structure : 20 Bytes. 
typedef struct InternetProtocol_Ipv4 {
    uint8_t VersionHeaderLength;
    uint8_t servicesfield;
    uint16_t tot_len;
    uint16_t id;
    uint16_t frag_off;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t check;
    uint8_t saddr[4];
    uint8_t daddr[4];
} InternetProtocolHeaderAccessor;

typedef struct InternetProtocol_Ipv6{
    uint8_t sourceaddr[16];
    uint8_t destinationaddr[16];

   /* union{
        uint32_t source_address_part1;
        uint32_t source_address_part2;
        uint32_t source_address_part3;
        uint32_t source_address_part4;

        uint32_t destination_address_part1;
        uint32_t destination_address_part2;
        uint32_t destination_address_part3;
        uint32_t destination_address_part4;
    }; */
} InternetProtocol_Ipv6header;

typedef struct  ARPProtocol { 
    uint8_t sourceAddressARP[4];
    uint8_t DestinationMac[6];
    uint8_t destinationAddressARP[4];
 } ARPHeaderAccess;

typedef struct UDPHeader{ // 8 bytes.
    uint16_t sourcePort;
    uint16_t destPort;
    uint16_t length;
    uint16_t checksum;
} UDPHead;

typedef struct TCPHeader { // 32 bytes but storing only Ports.
    uint16_t sourcePort;
    uint16_t destPort;
    uint32_t sequence_num;
    uint32_t ack_num;
    uint8_t data_offset :4, reserved: 4;
    uint8_t tcp_flags;
    uint32_t window_size;
    uint16_t checksum;
    uint16_t urg_pointer;
 } TCPHead;
