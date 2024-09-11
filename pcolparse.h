#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>

struct IP{
    unsigned char version;
    unsigned char IHL; //Length of internet header in 32 bit words
    unsigned char type_of_service;
    unsigned short total_length; //Total Length is the length of the datagram, measured in octets, including internet header and data.
    struct in_addr source_address;
    struct in_addr destination_address;

};

struct TCP{
    unsigned short source_port;
    unsigned short dest_port;
    unsigned char data_offset; //Number of 32 bit words in TCP header
    char* data;
};

struct Packed_list;
typedef struct IP IP_packet;
typedef struct TCP TCP_packet;

//Implemented as linked list as I am unsure of how many packets there will be
typedef struct pack_list {
    TCP_packet* tcp;
    IP_packet* ip;
    struct pack_list* next;
} pack_list;

#ifdef __cplusplus
    extern "C" IP_packet* parse_ip_packet(FILE** f, int offset);

    extern "C" TCP_packet* parse_tcp_packet(FILE** fp, int offset);

    extern "C" void free_pack_list(pack_list* p);

    extern "C" pack_list* parse_packets(FILE** fp);

    extern "C" pack_list* parse_tcp_ip_packets(FILE** fp, int offset); // Parse TCp, IP pair

#else
    IP_packet* parse_ip_packet(FILE** f, int offset);

    TCP_packet* parse_tcp_packet(FILE** fp, int offset);

    void free_pack_list(pack_list* p);

    pack_list* parse_packets(FILE** fp);

    pack_list* parse_tcp_ip_packets(FILE** fp, int offset); // Parse TCp, IP pair

#endif


//Start of file is where IP packet is
