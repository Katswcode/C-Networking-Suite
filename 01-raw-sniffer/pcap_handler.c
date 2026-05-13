// pcap_handler.c file that contains the implementation of the functions to handle the pcap file, such as initializing the file and writing packets to it.

#include "pcap_handler.h"
#include <sys/time.h>

FILE* pcap_init(const char* filename) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) return NULL;

    pcap_hdr_t global_hdr = {
        .magic_number = 0xa1b2c3d4,
        .version_major = 2,
        .version_minor = 4,
        .thiszone = 0,
        .sigfigs = 0,
        .snaplen = 65535,
        .network = 1  // Ethernet
    };

    fwrite(&global_hdr, sizeof(pcap_hdr_t), 1, fp);
    fflush(fp);
    return fp;
}

void pcap_write_packet(FILE* fp, const unsigned char* data, int size) {
    if (!fp) return;

    struct timeval tv;
    gettimeofday(&tv, NULL);

    pcaprec_hdr_t pkt_hdr = {
        .ts_sec = (uint32_t)tv.tv_sec,
        .ts_usec = (uint32_t)tv.tv_usec,
        .incl_len = (uint32_t)size,
        .orig_len = (uint32_t)size
    };

    fwrite(&pkt_hdr, sizeof(pcaprec_hdr_t), 1, fp);
    fwrite(data, size, 1, fp);
    fflush(fp);
}