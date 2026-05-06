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

// Function to get the name of the port based on the port number

const char* get_port_name(uint16_t port) 

{
    switch (port) {
        case 80:   return "HTTP";
        case 443:  return "HTTPS (TLS)";
        case 53:   return "DNS";
        case 22:   return "SSH";
        case 21:   return "FTP";
        case 123:  return "NTP";
        default:   return "Unknown";
    }
}


// start main function to create the sniffer

int main(int argc, char const *argv[])

{

    // Create a conditional to check that the argument counter read 2 words (the name of the program and the network interface)

    if( argc != 2)
    
    {

        printf("The quantity of argc is different than 2, the result is %d \n", argc);

        return 1;
    }

    // If the number is 2 we can start developing the sniffer

    else

    {

        // Check the number of arguments counted and the number of the Network interface

        printf("The number of argc is %d \n",argc);
        
        printf("The network interface is %s \n", argv[1]);
        
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


    // Creating the buffer to save data memory       

    unsigned char buffer [65536];

    // Creating while to repeatly capture data    

    // open file in write binary mode to save the captured packets in a pcap file

    FILE *logfile = fopen("capture.pcap", "wb");
    if(logfile == NULL) {
        printf("Error al abrir el archivo PCAP.\n");
        return 1;
    }

    // fill and write the global header of the pcap file

    pcap_hdr_t global_hdr;
    global_hdr.magic_number = 0xa1b2c3d4; // Wireshark search magic number to identify the file as a pcap file
    global_hdr.version_major = 2;
    global_hdr.version_minor = 4;
    global_hdr.thiszone = 0;
    global_hdr.sigfigs = 0;
    global_hdr.snaplen = 65535; // max length of captured packets
    global_hdr.network = 1;     // Refers to layer 2 (Ethernet)
    fwrite(&global_hdr, sizeof(pcap_hdr_t), 1, logfile);
    fflush(logfile); // forze writing the header to the file

    while(1) 
    
    {

    // Typecasting the buffer reading the value trough eth  

    struct ethhdr *eth = (struct ethhdr *)buffer;


    // Creting the reciving from function to recive data from the raw socket and collecting them in the buffer

    int data_size = recvfrom(raw_socket, buffer, 65536, 0, NULL, NULL);

    // 1. get the current timestamp to fill the packet header of the pcap file (we use gettimeofday to get the time in seconds and microseconds)

        struct timeval tv;
        gettimeofday(&tv, NULL);

        // 2. fill the packet header

        pcaprec_hdr_t pkt_hdr;
        pkt_hdr.ts_sec = tv.tv_sec;
        pkt_hdr.ts_usec = tv.tv_usec;
        pkt_hdr.incl_len = data_size; // captured size of the packet (could be smaller than orig_len if snaplen is smaller)
        pkt_hdr.orig_len = data_size; // original size of the packet (could be larger than incl_len if snaplen is smaller)

        // 3. write the packet header and raw data to the pcap file

        fwrite(&pkt_hdr, sizeof(pcaprec_hdr_t), 1, logfile);
        fwrite(buffer, data_size, 1, logfile);
        fflush(logfile); // save in real time the captured packet in the pcap file

        // If the data size is less than 0 there is an error if not print the length of the packet

        if(data_size < 0)
    
        {

        printf("Error reciving packet, data size is: %d", data_size);

        }

        else
    
        {

        printf("The length of the packet is: %d \n", data_size);

        // printing the MAC destiny, origin and type of the packets
        
        printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_dest[0], eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);

        printf("%.2X:%.2X:%.2X:%.2X:%.2X:%.2X \n", eth->h_source[0], eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);

        printf("%.4X \n", eth->h_proto);

            // ntohs (Network To Host Short) fliping bytes to allows processor to read it correctly

            if(ntohs(eth->h_proto) == 0x0800) 

            {

            printf("¡Catching IPv4 packets! \n");

            // Creating a casting to read ip destiny and origin addresses (we sum the size of ethhdr to buffer to skip the ethernet layer and go to ip layer)

            struct iphdr *ip = (struct iphdr *)(buffer + sizeof(struct ethhdr));

            struct in_addr source_ip, dest_ip;

            source_ip.s_addr = ip->saddr;

            dest_ip.s_addr = ip->daddr;

            // inet_ntoa: Internet Network To ASCII (byte converter to ASCII readable text)

            //printing IP source addresses and destination addresses

            printf("IP Origin: %s \n", inet_ntoa(source_ip));

            printf("IP Destination: %s \n", inet_ntoa(dest_ip));

            unsigned char *payload = buffer + sizeof(struct ethhdr) + (ip->ihl * 4);

            int payload_size = data_size - (sizeof(struct ethhdr) + (ip->ihl * 4));

            printf("Payload (%d bytes):\n", payload_size);
        
                for(int i = 0; i < payload_size; i++) 
                
                {
        
                    if(payload[i] >= 32 && payload[i] <= 126)
                
                    { 
        
                    printf("%c", payload[i]);
                
                    }

                    else
                
                    {

                    printf(".");
                
                    }

                }

            printf("\n------------------------------\n");

                // ICMP protocol

                if(ip->protocol == 1) 
        
                { 

                struct icmphdr *icmp = (struct icmphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));
    
                printf("ICMP (PING) DETECTED \n");

                printf("Type: %d\n", icmp->type);
    
                    if(icmp->type == 8) printf("It's a Request\n");

                    if(icmp->type == 0) printf("It's a Reply\n");   

                }

                // TCP protocol

                if(ip->protocol == 6) 
        
                { 

                struct tcphdr *tcp = (struct tcphdr *)(buffer + sizeof(struct ethhdr) + (ip->ihl * 4));

                printf("TCP Port: %u (%s)\n", ntohs(tcp->source), get_port_name(ntohs(tcp->source)));
        
                }

                // UDP protocol

                if(ip->protocol == 17)
                
                {

                struct udphdr *udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + (ip->ihl *4));

                printf("UDP Port: %u (%s)\n", ntohs(udp->source), get_port_name(ntohs(udp->source))); 

                }
        
            } // if IPv4 condition end

            else 

            {

            printf(" ⚠️ Catching packets, but not IPv4 ⚠️ \n");

            }


        }
    

    } // while(1) finish


    } // else finish

    return 0 ;

}