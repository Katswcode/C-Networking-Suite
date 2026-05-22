// app analyzer.c, this file contains the implementation of the function to analyze DNS packets, we will parse the DNS header and print the relevant information about the transaction, such as
// the transaction ID, the type of packet (query or response), and the number of questions and answers.

#include "app_analyzer.h"
#include <stdio.h>
#include <arpa/inet.h> // for ntohs function
#include <string.h> // for memset function

void analyze_dns(const unsigned char *payload, int payload_size)

{
    if (payload_size < (int)sizeof(dns_header_t))

    {

      return; // The payload is too small to contain a valid DNS header, we ignore it

    }

    // Casting the payload to our dns_header_t structure to easily access the fields of the DNS header, we can do this because the DNS header has a fixed size of 12 bytes and the structure is defined to match that format

    dns_header_t *dns = (dns_header_t *)payload;

    // Converting the fields from network byte order to host byte order using ntohs function, this is necessary because the fields in the DNS header are transmitted in big-endian format and we need to convert them to the correct format for our machine architecture

    uint16_t flags = ntohs(dns->flags);

    uint16_t questions = ntohs(dns->q_count);

    uint16_t answers = ntohs(dns->ans_count);

    printf("\n    [Layers 7] 🔍 DNS Protocol Detected:\n");

    printf("    ├─ Transaction ID: 0x%04X\n", ntohs(dns->id));

    // Bitmasking: 15 bytes for the flags, we will check the first bit (0x8000) to determine if it's a query or a response, if the bit is 0 it's a query, if it's 1 it's a response

    if ((flags & 0x8000) == 0)

    {

        printf("    ├─ Type: QUERY (Pregunta)\n");

    } else

    {
        printf("    ├─ Type: RESPONSE (Respuesta)\n");

    }

    printf("    ├─ Questions: %u\n", questions);

    printf("    └─ Answers:   %u\n", answers);
}


// Implementing the analyze_http function to detect HTTP traffic in the payload of TCP packets, we will look for the common HTTP methods (GET, POST) and the HTTP version (HTTP/1.1, HTTP/2)
// to identify if the payload contains HTTP data, if it does we will print the request/response line and the target host if it's present in the headers.

void analyze_http(const unsigned char *payload, int payload_size)

{
    // No data to analyze, we return immediately

    if (payload_size <= 0) return;

    // HTTP is plain text. We will look for the common HTTP methods (GET, POST, HTTP/)

    // We use strncmp to compare the beginning of the payload with the HTTP methods, we check for "GET ", "POST ", and "HTTP/" to cover both requests and responses. We also ensure that we are not reading beyond the payload size.

    if (strncmp((const char *)payload, "GET ", 4) == 0 ||

        strncmp((const char *)payload, "POST ", 5) == 0 ||

        strncmp((const char *)payload, "HTTP/", 5) == 0)
    {
        printf("\n    [Layer 7] 🌐 HTTP Protocol Detected:\n");

        // We will print the first line of the message (where the URL or status is located)

        printf("    ├─ Request/Response Line: ");

        for (int i = 0; i < payload_size; i++)
        {
            if (payload[i] == '\r' || payload[i] == '\n')
            {
                break; // End of the first line
            }
            // We will print only readable characters (ASCII between 32 and 126)

            if (payload[i] >= 32 && payload[i] <= 126)
            {
                printf("%c", payload[i]);
            }
        }
        printf("\n");

        // Extra challenge: Search for the domain (Host:)

        // We will use strstr to find the "Host: " header in the payload, if it's found we will print the target host, we will also ensure that we are not reading beyond the payload size.

        char *host_ptr = strstr((const char *)payload, "Host: ");

        if (host_ptr != NULL)

        {
            printf("    ├─ Target Host: ");

            host_ptr += 6; // Move the pointer past "Host: " to get to the actual host value

            while (*host_ptr != '\r' && *host_ptr != '\n' && *host_ptr != '\0')

            {
                printf("%c", *host_ptr);

                host_ptr++;
            }

            printf("\n");
        }
    }
}
