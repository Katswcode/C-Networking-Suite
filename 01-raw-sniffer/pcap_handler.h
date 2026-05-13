// pcap_handler.h file that contains the definitions of the functions to handle the pcap file, such as initializing the file and writing packets to it. 

// This allows us to separate the logic of handling the pcap file from the main sniffer logic, making the code more organized and modular.

#ifndef PCAP_HANDLER_H
#define PCAP_HANDLER_H

#include <stdio.h>
#include <stdint.h>

// Global Header Structure of PCAP

typedef struct pcap_hdr_s 

{
    uint32_t magic_number;   /* magic number */
    uint16_t version_major;  /* major version number */
    uint16_t version_minor;  /* minor version number */
    int32_t  thiszone;       /* GMT to local correction */
    uint32_t sigfigs;        /* accuracy of timestamps */
    uint32_t snaplen;        /* max length of captured packets, in octets */
    uint32_t network;        /* data link type (1 = Ethernet) */
} pcap_hdr_t;

// Packet Header Structure of PCAP

typedef struct pcaprec_hdr_s 

{
    uint32_t ts_sec;         /* timestamp seconds */
    uint32_t ts_usec;        /* timestamp microseconds */
    uint32_t incl_len;       /* number of octets of packet saved in file */
    uint32_t orig_len;       /* actual length of packet */
} pcaprec_hdr_t;

// Function prototypes for handling the pcap file

FILE* pcap_init(const char* filename);

void pcap_write_packet(FILE* fp, const unsigned char* data, int size);

#endif