# C-Networking-Suite 🚀

A professional collection of low-level networking tools developed in C to explore the OSI model, memory management, and Linux Socket API.

## 🛠 Project 01: Raw Packet Sniffer

A Layer 2 (Data Link) sniffer that captures and decodes Ethernet frames and IPv4 packets directly from the network interface.

### Key Technical Features:

* **Raw Sockets:** Implements `AF_PACKET` and `SOCK_RAW` to capture traffic bypassing the standard TCP/IP stack.
* **Memory & Pointers:** Advanced use of pointer arithmetic to navigate protocol headers (Ethernet, IP, TCP/UDP).
* **Endianness Handling:** Proper byte-order conversion using `ntohs()` and `htons()` for network data integrity.
* **Protocol Analysis:** Supports real-time decoding of MAC addresses, IP addresses, and transport layer payloads.

### How to Build and Run

1. **Compile:**

   ```bash

   gcc 01-raw-sniffer/sniffer.c -o sniffer

   **Execute:**

   ```bash

   sudo ./sniffer [interface_name]


Developed as part of a deep-dive into embedded systems and network engineering.