#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <poll.h>
#include <errno.h>

#define PACKET_SIZE 64
#define TIMEOUT_MS 100 // Short timeout for speed

struct packet {
    struct icmphdr hdr;
    char msg[PACKET_SIZE - sizeof(struct icmphdr)];
};

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

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: sudo %s -a <ip> -c <subnet_cidr>\n", argv[0]);
        return 1;
    }

    char *network_ip_str = NULL;
    int cidr = -1;

    // Parse arguments manually to support -a and -c order
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-a") == 0 && i + 1 < argc) {
            network_ip_str = argv[i + 1];
        } else if (strcmp(argv[i], "-c") == 0 && i + 1 < argc) {
            cidr = atoi(argv[i + 1]);
        }
    }

    if (!network_ip_str || cidr == -1) {
        printf("Missing arguments.\n");
        return 1;
    }

    // Calculate Network Range
    uint32_t ip_bin = ntohl(inet_addr(network_ip_str));
    uint32_t mask = (0xFFFFFFFF << (32 - cidr));
    uint32_t start_ip = (ip_bin & mask) + 1; // First usable IP
    uint32_t end_ip = (ip_bin | ~mask) - 1;  // Last usable IP
    
    // Correction for scanning the *whole* subnet including .0 if desired, 
    // but usually we scan usable hosts. Let's stick to usability.

    printf("Scanning %s/%d:\n", network_ip_str, cidr);

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket failed");
        return 1;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;

    // Loop through all IPs
    for (uint32_t current = start_ip; current <= end_ip; current++) {
        struct in_addr current_in;
        current_in.s_addr = htonl(current);
        dest_addr.sin_addr = current_in;

        // Prepare Packet
        struct packet pckt;
        memset(&pckt, 0, sizeof(pckt));
        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.code = 0;
        pckt.hdr.un.echo.id = htons(1234);
        pckt.hdr.un.echo.sequence = htons(current & 0xFFFF); // Use IP part as seq
        pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

        // Send
        if (sendto(sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
            continue; 
        }

        // Wait for reply
        struct pollfd pfd;
        pfd.fd = sockfd;
        pfd.events = POLLIN;
        
        if (poll(&pfd, 1, TIMEOUT_MS) > 0) {
            unsigned char buf[1024];
            struct sockaddr_in r_addr;
            socklen_t len = sizeof(r_addr);
            int bytes = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&r_addr, &len);
            
            if (bytes > 0) {
                struct iphdr *ip = (struct iphdr *)buf;
                int iphdr_len = ip->ihl * 4;
                struct icmphdr *icmp = (struct icmphdr *)(buf + iphdr_len);

                // Check if it's a reply to our ping
                if (icmp->type == ICMP_ECHOREPLY && icmp->un.echo.id == htons(1234)) {
                     // Check if the reply comes from the IP we just pinged
                     if (r_addr.sin_addr.s_addr == current_in.s_addr) {
                         printf("%s\n", inet_ntoa(current_in));
                     }
                }
            }
        }
    }

    printf("Scan Complete!\n");
    close(sockfd);
    return 0;
}