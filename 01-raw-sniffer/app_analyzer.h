// app analyzer.h - Header file for the application layer analyzer of our sniffer, we will use it to define the structure of the DNS header and the function prototype for analyzing DNS packets

#ifndef APP_ANALYZER_H
#define APP_ANALYZER_H

#include <stdint.h>

// standard DNS header structure, we will use it to parse the DNS packets and extract the relevant information for our sniffer

typedef struct

{
    uint16_t id;          // Unique identifier of the transaction
    uint16_t flags;       // Flags (Query/Response, Error code, etc.)
    uint16_t q_count;     // Number of questions (Questions)
    uint16_t ans_count;   // Number of answers (Answer RRs)
    uint16_t auth_count;  // Number of authority records
    uint16_t add_count;   // Number of additional records
} dns_header_t;

// Function prototypes for analyzing DNS and HTTP packets, we will implement these functions in app_analyzer.c to detect and parse the application layer protocols in the captured packets

void analyze_dns(const unsigned char *payload, int payload_size);

void analyze_http(const unsigned char *payload, int payload_size);

#endif