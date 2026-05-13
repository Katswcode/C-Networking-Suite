// packet_utils.c file that contains the implementation of the utility functions used in the project, such as getting the port name and hex dumping the data.

# include "packet_utils.h"

// Function to get the name of the port based on the port number

const char* get_port_name(uint16_t port) 

{
    switch (port) 

    {
        case 80:   return "HTTP";
        case 443:  return "HTTPS (TLS)";
        case 53:   return "DNS";
        case 22:   return "SSH";
        case 21:   return "FTP";
        case 123:  return "NTP";
        default:   return "Unknown";
    }
}



// Hex Dump function to orginize the payload in a more readable format, showing the hexadecimal values and their corresponding ASCII characters (if printable) for better analysis of the captured packets

// data: pointer to the data to be dumped, size: size of the data in bytes

void hex_dump(const unsigned char *data, int size) 

{
    for (int i = 0; i < size; i += 16) 
    
    {

        // Printing the offset of the line in hexadecimal format, we use %04x to print it as a 4 digit hexadecimal number, and we add two spaces after it for better readability

        printf("%04x  ", i);
        
        for (int j = 0; j < 16; j++) 
        
        {

            //

            if (i + j < size)

                printf("%02x ", data[i + j]);
            else

                printf("   ");

        }

        printf(" | ");

        for (int j = 0; j < 16; j++) 
        
        {
            
            if (i + j < size) 
            
            {
                unsigned char byte = data[i + j];
                
                printf("%c", (byte >= 32 && byte <= 126) ? byte : '.');
            }
        }

        printf("\n");
    }
}

// Function to print the final report of the sniffer, showing the total number of packets captured, the number of IPv4 packets, TCP packets, UDP packets, ICMP packets, non-IPv4/other Ethernet types and the total number of bytes captured.

void print_final_stats(sniffer_stats_t stats) {
    printf("\n------------------------------------\n");
    printf("           FINAL REPORT             \n");
    printf("------------------------------------\n");
    printf(" Total Packets:    %u\n", stats.total_packets);
    printf(" IPv4 Packets:     %u\n", stats.ipv4_packets);
    printf("  - TCP:           %u\n", stats.tcp_packets);
    printf("  - UDP:           %u\n", stats.udp_packets);
    printf("  - ICMP:          %u\n", stats.icmp_packets);
    printf(" Non-IPv4/Other:   %u\n", stats.other_eth_types);
    printf(" Total Bytes:      %lu bytes\n", stats.total_bytes);
    printf("------------------------------------\n");
}