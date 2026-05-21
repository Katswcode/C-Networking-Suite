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

// Main function that will be called by the sniffer to analyze the application layer packet

void analyze_dns(const unsigned char *payload, int payload_size);

#endif