# Makefile for the packet sniffer project

CC = gcc

CFLAGS = -Wall -Wextra

OBJ = sniffer.o pcap_handler.o packet_utils.o app_analyzer.o

TARGET = sniffer

all:	$(TARGET)

$(TARGET):	$(OBJ)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJ)

%.o: %.c
	$(CC) $(CFLAGS) -c $<

clean:
	rm -f *.o $(TARGET) capture.pcap