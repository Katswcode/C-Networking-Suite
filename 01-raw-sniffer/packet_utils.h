// packet_utils.h file that contains the definitions of the utility functions used in the project, such as getting the port name and hex dumping the data.

#ifndef PACKET_UTILS_H

#define PACKET_UTILS_H

#include <stdint.h>
#include <stdio.h>

const char* get_port_name(uint16_t port);

void hex_dump(const unsigned char *data, int size);

#endif