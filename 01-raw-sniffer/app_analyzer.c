#include "app_analyzer.h"
#include <stdio.h>
#include <arpa/inet.h> // Para ntohs

void analyze_dns(const unsigned char *payload, int payload_size) {
    if (payload_size < (int)sizeof(dns_header_t)) {
        return; // El paquete es demasiado pequeño para ser DNS válido
    }

    // Casteamos el inicio del payload directamente a nuestra estructura
    dns_header_t *dns = (dns_header_t *)payload;

    // Convertimos los campos de Network a Host byte order
    uint16_t flags = ntohs(dns->flags);
    uint16_t questions = ntohs(dns->q_count);
    uint16_t answers = ntohs(dns->ans_count);

    printf("\n    [Layers 7] 🔍 DNS Protocol Detected:\n");
    printf("    ├─ Transaction ID: 0x%04X\n", ntohs(dns->id));

    // Bitmasking: El bit 15 (0x8000) define si es Query (0) o Response (1)
    if ((flags & 0x8000) == 0) {
        printf("    ├─ Type: QUERY (Pregunta)\n");
    } else {
        printf("    ├─ Type: RESPONSE (Respuesta)\n");
    }

    printf("    ├─ Questions: %u\n", questions);
    printf("    └─ Answers:   %u\n", answers);
}