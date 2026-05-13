// sniffer.c file that contains the main logic of the packet sniffer, including the creation of the raw socket, capturing packets, filtering by IP, and writing the captured packets to a pcap file. 

// It also includes signal handling for graceful shutdown and utility functions for hex dumping and getting port names.

#define _GNU_SOURCE
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <stdint.h>
#include <sys/time.h>
#include <string.h>
#include <signal.h>
#include <stdlib.h>

#include "pcap_handler.h"
#include "packet_utils.h"

FILE *logfile = NULL; // Global variable to hold the file pointer for the pcap file, we use it in the signal handler to close the file when the user interrupts the program with Ctrl+C

sniffer_stats_t stats = {0}; // Initializing the stats structure to keep track of the captured packets and their types, we will update this structure as we capture packets and use it to print a final report when the user interrupts the program

// Function to handle Ctrl+C

void handle_sigint(int sig) 

{
    printf("\n\n[+] Capture interrupted by the user (Signal %d).\n", sig);

    print_final_stats(stats); // Print the final report of the sniffer using the stats structure that we have been updating during the capture

    if (logfile != NULL) 

    {
        fclose(logfile);

        printf("[+] File 'capture.pcap' closed correctly. Data safe!\n");
    }
    
    printf("[+] exiting sniffer...\n");

    exit(0); // finish the program with exit code 0 to indicate successful termination
}

// start main function to create the sniffer

int main(int argc, char const *argv[])

{

    // register the signal handler for SIGINT to allow graceful shutdown of the program when the user presses Ctrl+C

    signal(SIGINT, handle_sigint);

    // allows us to run the program with the following syntax: ./sniffer <interface> [ip_to_filter] (the second parameter is optional to filter by IP)

    if (argc < 2 || argc > 3)
    
    {
        printf("Use: %s <Interface> [filter ip]\n", argv[0]);

        return 1;
    }

    const char *target_ip = NULL;

    if (argc == 3)
    
    {

        // we use argv[2] to get the IP address to filter and save it in target_ip variable

        target_ip = argv[2];

        printf("Mode: Filter by IP: %s\n", target_ip);
    }

    else
    
    {
        printf("Mode: Capturing all traffic on %s\n", argv[1]);
    }
    
    // Initialize the pcap file to save the captured packets, we use the pcap_init function from pcap_handler.c to create the file and write the global header, if there is an error we print it and exit the program

    logfile = pcap_init("capture.pcap");
    
    if (logfile == NULL) 
    
    {
        perror("Error initializing PCAP");
        
        return 1;
    }

        /*raw socket function that has AF_PACKET (tell that  we want to be in layer 2 of the OSI model), SOCK RAW (Provides the raw packet, including the link-level header (Ethernet)), 
        and the htons filter that allow us to capture all protocols with the ETH_P_ALL parameter */ 
        
        int raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));

        // if the raw_socket has a negative number we have and error if not we have the ID of the socket

        if (raw_socket < 0)

        {

            perror("Error opening the socket");

        }

        else 

        {

            printf("THe socket is open with the following ID: %d \n", raw_socket);

        }

    
        if (setsockopt(raw_socket, SOL_SOCKET, SO_BINDTODEVICE, argv[1], strlen(argv[1])) < 0) 
        
        {
        
        perror("Error Binding the socket to the interface");
        
        }

    // Creating the buffer to save data memory       

    unsigned char buffer [65536];

    while(1) 
    
    {

    // Typecasting the buffer reading the value trough eth  

    struct ethhdr *eth = (struct ethhdr *)buffer;


    // Creting the reciving from function to recive data from the raw socket and collecting them in the buffer

    int data_size = recvfrom(raw_socket, buffer, 65536, 0, NULL, NULL);

        // If the data size is less than 0 there is an error if not print the length of the packet

        if(data_size < 0)
    
        {

        printf("Error reciving packet, data size is: %d", data_size);
        
        continue;

        }

        else
    
        {

            // Update the stats structure with the captured packet, we increment the total_packets and add the data_size to total_bytes

            stats.total_packets++;
            stats.total_bytes += data_size;

            // Safe the captured packet in the pcap file using the pcap_write_packet function from pcap_handler.c, we pass the file pointer, the buffer with the raw data and the size of the data

            pcap_write_packet(logfile, buffer, data_size);

            // ntohs (Network To Host Short) fliping bytes to allows processor to read it correctly

            if(ntohs(eth->h_proto) == 0x0800) 

            {

            // Creating a casting to read ip destiny and origin addresses (we sum the size of ethhdr to buffer to skip the ethernet layer and go to ip layer)

            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

            // Convert the ip addresses from binary to human readable format using inet_ntop and store them in src_ip_str and dst_ip_str

            char src_ip_str[INET_ADDRSTRLEN], dst_ip_str[INET_ADDRSTRLEN];

            inet_ntop(AF_INET, &(ip->saddr), src_ip_str, INET_ADDRSTRLEN);

            inet_ntop(AF_INET, &(ip->daddr), dst_ip_str, INET_ADDRSTRLEN);

            // filter logic

            // if the user provided a target IP to filter, we compare the source and destination IPs of the packet with the target IP, if neither matches, we skip printing the packet and continue to the next iteration of the loop to capture the next packet

            if (target_ip != NULL) 
            
            {

                if (strcmp(src_ip_str, target_ip) != 0 && strcmp(dst_ip_str, target_ip) != 0) 

                {
                    // dont print the packet if it doesn't match the filter and continue to the next iteration of the loop to capture the next packet

                    continue; 
                }
            }

            // If we reach here, it means the packet passed the filter (or there's no filter)

            // If the packet passed the filter, print its details (length, MAC addresses, IP addresses, payload, and protocol information)

            printf("\n=================================================\n");

            printf("¡Catching IPv4 packets! \n");

            printf("The length of the packet is: %d \n", data_size);

            printf("MAC Dest: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_dest[0], eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);

            printf("MAC Src: %.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_source[0], eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);

            printf("IP Origin: %s \n", src_ip_str);
            
            printf("IP Destination: %s \n", dst_ip_str);


            unsigned char *payload = buffer + sizeof(struct ethhdr) + (ip->ihl * 4);

            int payload_size = data_size - (sizeof(struct ethhdr) + (ip->ihl * 4));

            printf("Payload (%d bytes):\n", payload_size);

                // if the payload size is greater than 0, we call the hex_dump function to print the payload in a readable format, if not we skip it

                if (payload_size > 0) 
                
                {

                hex_dump(payload, payload_size);

                }
                    
            printf("\n------------------------------\n");

                // ICMP protocol

                if(ip->protocol == 1) 
        
                { 

                    stats.icmp_packets++;

                struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
    
                printf("ICMP (PING) DETECTED \n");

                printf("Type: %d\n", icmp->type);
    
                    if(icmp->type == 8) printf("It's a Request\n");

                    if(icmp->type == 0) printf("It's a Reply\n");   

                }

                // TCP protocol

                if(ip->protocol == 6) 
        
                { 

                    stats.tcp_packets++;

                struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));

                printf("TCP protocol | Origin Port: %u (%s) | Destiny Port: %u (%s)\n", ntohs(tcp->source), get_port_name(ntohs(tcp->source)), ntohs(tcp->dest), get_port_name(ntohs(tcp->dest)));
        
                printf("Flags: ");

                    // C determines different values than 0 as true, so if the flag is set it will print the corresponding flag name"

                    if (tcp->syn) printf("[SYN] (Sync) ");

                    if (tcp->ack) printf("[ACK] (Acknowledge) ");

                    if (tcp->fin) printf("[FIN] (Finish) ");

                    if (tcp->rst) printf("[RST] (Reset) ");

                    if (tcp->psh) printf("[PSH] (Push) ");

                    if (tcp->urg) printf("[URG] (Urgent) ");

                    printf("\n");



                }

                // UDP protocol

                if(ip->protocol == 17)
                
                {

                    stats.udp_packets++;

                struct udphdr *udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + (ip->ihl *4));

                printf("UDP protocol | Origin Port: %u (%s) | Destiny Port: %u (%s)\n", ntohs(udp->source), get_port_name(ntohs(udp->source)), ntohs(udp->dest), get_port_name(ntohs(udp->dest))); 

                }

            } // if IPv4 condition end

            else 

            {
                // plus one to count the packet in the other_eth_types if it's not IPv4

                stats.other_eth_types++;

            // print a warning if the packet is not IPv4 and show the protocol that is using in hexadecimal format

            printf(" ⚠️ packet detected but not IPv4, protocol: 0x%04x ⚠️ \n", ntohs(eth->h_proto));

            }

        }
    

    } // while(1) finish

    return 0 ;

} // main function finish