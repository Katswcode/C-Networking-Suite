# C-Networking-Suite 🚀

A professional collection of low-level networking tools developed in C to explore the OSI model, memory management, and Linux Socket API.

## 🛠 Project 01: Raw Packet Sniffer

A Layer 2 (Data Link) sniffer that captures and decodes Ethernet frames and IPv4 packets directly from the network interface.

### Key Technical Features:

* **Raw Sockets:** Implements `AF_PACKET` and `SOCK_RAW` to capture traffic bypassing the standard TCP/IP stack.
* **Modular Design:** Divided into specialized modules (`pcap_handler`, `packet_utils`) for better maintainability.
* **Memory & Pointers:** Advanced use of pointer arithmetic and typecasting to navigate nested protocol headers.
* **Endianness Handling:** Proper byte-order conversion using `ntohs()` for network data integrity.
* **PCAP Logging:** Saves captured traffic into standard `.pcap` files, fully compatible with Wireshark.

### How to Build and Run

1. **Compile:**
   ```bash

   make

2. **Execute:**
   ```bash

      #Capture all traffic on an interface:

      sudo ./sniffer [interface_name]

      #Capture and filter by a specific IP:

      sudo ./sniffer [interface_name] [target_ip]

3. **Cleanup**

   ```bash

   make clean


### Requirements

    Linux OS (tested on Ubuntu)

    Root privileges (required for raw sockets)

    GCC & Make

Developed as part of a deep-dive into embedded systems and network engineering.