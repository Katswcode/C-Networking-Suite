#ifndef PACKET_UTILS_H
#define PACKET_UTILS_H

#include <stdint.h>
#include <stdio.h>

// Estructura para reportar la salud de la red
typedef struct {
    uint32_t total_packets;
    uint32_t ipv4_packets;
    uint32_t tcp_packets;
    uint32_t udp_packets;
    uint32_t icmp_packets;
    uint32_t other_eth_types;
    uint64_t total_bytes;
} sniffer_stats_t;

void hex_dump(const unsigned char *data, int size);
const char* get_port_name(uint16_t port);
// Nueva función para imprimir el reporte final
void print_final_stats(sniffer_stats_t stats);

#endif