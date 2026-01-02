#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <sys/time.h>
#include <poll.h>
#include <errno.h>

#define MAX_HOPS 30             // Max hops as per instructions 
#define PROBES_PER_HOP 3        // 3 packets per hop 
#define PACKET_SIZE 64
#define TIMEOUT_MS 1000         // 1 second timeout 

// Packet structure containing both IP and ICMP headers
struct packet {
    struct iphdr ip;
    struct icmphdr icmp;
    char payload[PACKET_SIZE - sizeof(struct iphdr) - sizeof(struct icmphdr)];
};

// Checksum function (Same as Ping) [cite: 316-356]
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

double get_time_diff_ms(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) * 1000.0 +
           (end->tv_usec - start->tv_usec) / 1000.0;
}

int main(int argc, char *argv[]) {
    if (argc != 3 || strcmp(argv[1], "-a") != 0) {
        fprintf(stderr, "Usage: sudo %s -a <destination>\n", argv[0]); // [cite: 116]
        return 1;
    }

    char *dest_str = argv[2];
    struct hostent *host = gethostbyname(dest_str);
    if (!host) {
        fprintf(stderr, "Error resolving hostname %s\n", dest_str);
        return 1;
    }

    struct sockaddr_in dest_addr;
    memset(&dest_addr, 0, sizeof(dest_addr));
    dest_addr.sin_family = AF_INET;
    memcpy(&dest_addr.sin_addr, host->h_addr, host->h_length);

    printf("traceroute to %s (%s), %d hops max\n", dest_str, inet_ntoa(dest_addr.sin_addr), MAX_HOPS);

    // Create RAW socket with IP_HDRINCL enabled 
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    int on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt IP_HDRINCL failed");
        return 1;
    }

    int destination_reached = 0;
    int pid = getpid();

    // Main Loop: TTL from 1 to 30 [cite: 140]
    for (int ttl = 1; ttl <= MAX_HOPS && !destination_reached; ttl++) {
        printf("%2d  ", ttl); // Print Hop Number
        fflush(stdout);

        struct in_addr responder_ip;
        responder_ip.s_addr = 0;
        int printed_ip = 0;

        // Inner Loop: 3 Probes per hop 
        for (int probe = 0; probe < PROBES_PER_HOP; probe++) {
            struct packet pckt;
            memset(&pckt, 0, sizeof(pckt));

            // 1. Build IP Header 
            pckt.ip.ihl = 5;
            pckt.ip.version = 4;
            pckt.ip.tos = 0;
            pckt.ip.tot_len = sizeof(pckt);
            pckt.ip.id = htons(pid);
            pckt.ip.frag_off = 0;
            pckt.ip.ttl = ttl; // Set current TTL
            pckt.ip.protocol = IPPROTO_ICMP;
            pckt.ip.saddr = 0; // Kernel will fill source IP
            pckt.ip.daddr = dest_addr.sin_addr.s_addr;
            // Note: On Linux with IP_HDRINCL, kernel calculates IP checksum if we leave it 0

            // 2. Build ICMP Header
            pckt.icmp.type = ICMP_ECHO;
            pckt.icmp.code = 0;
            pckt.icmp.un.echo.id = htons(pid);
            pckt.icmp.un.echo.sequence = htons(ttl * 10 + probe); // Unique sequence
            pckt.icmp.checksum = checksum(&pckt.icmp, sizeof(pckt) - sizeof(struct iphdr));

            struct timeval start, end;
            gettimeofday(&start, NULL);

            // 3. Send Packet
            if (sendto(sockfd, &pckt, sizeof(pckt), 0, (struct sockaddr *)&dest_addr, sizeof(dest_addr)) <= 0) {
                perror("sendto");
            }

            // 4. Wait for reply (Poll)
            struct pollfd pfd;
            pfd.fd = sockfd;
            pfd.events = POLLIN;
            int ret = poll(&pfd, 1, TIMEOUT_MS); // 1 second timeout 

            if (ret <= 0) {
                printf("* "); // Timeout
                fflush(stdout);
            } else {
                unsigned char buf[1024];
                struct sockaddr_in r_addr;
                socklen_t len = sizeof(r_addr);
                int bytes = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&r_addr, &len);
                
                gettimeofday(&end, NULL);
                double rtt = get_time_diff_ms(&start, &end);

                if (bytes > 0) {
                    struct iphdr *recv_ip = (struct iphdr *)buf;
                    int ip_len = recv_ip->ihl * 4;
                    struct icmphdr *recv_icmp = (struct icmphdr *)(buf + ip_len);

                    // Logic: Validate if this packet is relevant to us
                    int is_ours = 0;

                    if (recv_icmp->type == ICMP_TIME_EXCEEDED) {
                        // Type 11: The payload contains the ORIGINAL IP header + first 8 bytes of ORIGINAL ICMP
                        // We need to dig deep to check the ID
                        struct iphdr *orig_ip = (struct iphdr *)(buf + ip_len + 8);
                        int orig_ip_len = orig_ip->ihl * 4;
                        struct icmphdr *orig_icmp = (struct icmphdr *)(buf + ip_len + 8 + orig_ip_len);
                        
                        if (orig_icmp->un.echo.id == htons(pid) && 
                            orig_icmp->un.echo.sequence == htons(ttl * 10 + probe)) {
                            is_ours = 1;
                        }
                    } else if (recv_icmp->type == ICMP_ECHOREPLY) {
                        // Type 0: Standard reply
                        if (recv_icmp->un.echo.id == htons(pid) &&
                            recv_icmp->un.echo.sequence == htons(ttl * 10 + probe)) {
                            is_ours = 1;
                            destination_reached = 1; // [cite: 142]
                        }
                    }

                    if (is_ours) {
                        if (!printed_ip) {
                            printf("%s ", inet_ntoa(r_addr.sin_addr)); // Print IP only once per line
                            printed_ip = 1;
                            responder_ip = r_addr.sin_addr;
                        }
                        printf("%.3fms ", rtt); // Print time [cite: 121]
                    } else {
                        // Received packet not for us (e.g., background traffic), count as * for this logic simplicity
                        // Ideally we should loop poll again, but simplified for assignment structure:
                        printf("* "); 
                    }
                }
            }
        }
        printf("\n");
    }

    close(sockfd);
    return 0;
}