#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/udp.h>
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

                printf("Protocol: TCP | Origin port: %d | Destiny port: %d \n",ntohs(tcp->source), ntohs(tcp->dest));
        
                }

                // UDP protocol

                if(ip->protocol == 17)
                
                {

                struct udphdr *udp = (struct udphdr*)(buffer + sizeof(struct ethhdr) + (ip->ihl *4));

                printf("Protocol UDP | Origin port: %d | Destiny port: %d \n", ntohs(udp->source), ntohs(udp->dest)); 

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