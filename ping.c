#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <time.h>
#include <fcntl.h>
#include <netdb.h>
#include <netinet/ip.h>
#include <sys/time.h>
#include <errno.h>
#include <poll.h>
#include <signal.h>
#include <limits.h>
#include <math.h>

#define PACKET_SIZE 64
#define TIMEOUT_MS 10000 // 10 seconds timeout [cite: 58, 292]

// Global variables for statistics and signal handling
int sockfd = -1;
char *addr_str = NULL;
int packets_transmitted = 0;
int packets_received = 0;
double rtt_min = 999999.0;
double rtt_max = 0.0;
double rtt_sum = 0.0;
double rtt_sq_sum = 0.0;
struct timeval start_prog; // To calculate total running time

// Packet structure
struct packet {
    struct icmphdr hdr;
    unsigned char msg[PACKET_SIZE - sizeof(struct icmphdr)];
};

// Checksum function [cite: 321-356]
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

// Function to calculate time difference in milliseconds
double get_time_diff_ms(struct timeval *start, struct timeval *end) {
    return (end->tv_sec - start->tv_sec) * 1000.0 +
           (end->tv_usec - start->tv_usec) / 1000.0;
}

// Signal handler to display statistics and exit [cite: 280-285]
void finish(int sig) {
    struct timeval end_prog;
    gettimeofday(&end_prog, NULL);
    double total_time = get_time_diff_ms(&start_prog, &end_prog);

    printf("\n--- %s ping statistics ---\n", addr_str ? addr_str : "unknown");
    printf("%d packets transmitted, %d received, time %.2fms\n",
           packets_transmitted, packets_received, total_time);

    if (packets_received > 0) {
            double avg = rtt_sum / packets_received;
            double mdev = sqrt((rtt_sq_sum / packets_received) - (avg * avg));

            printf("rtt min/avg/max/mdev = %.3f/%.3f/%.3f/%.3f ms\n",
                rtt_min, avg, rtt_max, mdev);
        }

    if (sockfd >= 0) close(sockfd);
    exit(0);
}

int main(int argc, char *argv[]) {
    struct sockaddr_in addr_con;
    struct hostent *hname;
    struct packet pckt;
    int opt;
    
    // Default values
    int count_limit = -1; // Infinite by default
    int flood_mode = 0;
    int seq_counter = 0; // Start with counter = 0 
    int my_pid = getpid();

    // Parse arguments
    while ((opt = getopt(argc, argv, "a:c:f")) != -1) {
        switch (opt) {
            case 'a':
                addr_str = optarg;
                break;
            case 'c':
                count_limit = atoi(optarg);
                break;
            case 'f':
                flood_mode = 1;
                break;
            default:
                fprintf(stderr, "Usage: %s -a <address> [-c <count>] [-f]\n", argv[0]);
                exit(1);
        }
    }

    if (addr_str == NULL) {
        fprintf(stderr, "Error: Address (-a) is required.\n");
        exit(1);
    }

    // Capture start time for statistics 
    gettimeofday(&start_prog, NULL);

    // Register signal handler (Ctrl+C) [cite: 285]
    signal(SIGINT, finish);

    // Resolve hostname
    hname = gethostbyname(addr_str);
    if (!hname) {
        fprintf(stderr, "Error: Could not resolve hostname %s\n", addr_str);
        exit(1);
    }

    // Configure destination address
    memset(&addr_con, 0, sizeof(addr_con));
    addr_con.sin_family = AF_INET;
    memcpy(&addr_con.sin_addr, hname->h_addr_list[0], hname->h_length);

    // Create Raw Socket
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) {
        perror("Socket creation failed (run with sudo?)");
        exit(1);
    }

    // Set TTL (optional but good practice to match output "ttl=...")
    int ttl_val = 64;
    if (setsockopt(sockfd, IPPROTO_IP, IP_TTL, &ttl_val, sizeof(ttl_val)) != 0) {
        perror("Set TTL option failed");
        // Proceed anyway
    }

    printf("Pinging %s with %d bytes of data:\n", addr_str, PACKET_SIZE);

    // Main Loop
    while (count_limit == -1 || packets_transmitted < count_limit) {
        
        // 1. Prepare Packet
        memset(&pckt, 0, sizeof(pckt));
        pckt.hdr.type = ICMP_ECHO;
        pckt.hdr.code = 0;
        pckt.hdr.un.echo.id = htons(my_pid); // Use PID to identify our packets
        pckt.hdr.un.echo.sequence = htons(seq_counter); // Sequence number 
        
        // Put current time in payload to calculate RTT later
        struct timeval start_packet_time;
        gettimeofday(&start_packet_time, NULL);
        memcpy(pckt.msg, &start_packet_time, sizeof(start_packet_time));
        
        pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

        // 2. Send Packet
        if (sendto(sockfd, &pckt, sizeof(pckt), 0,
                   (struct sockaddr *)&addr_con, sizeof(addr_con)) <= 0) {
            perror("Packet send failed");
        } else {
            packets_transmitted++;
            if (flood_mode) {
                write(STDOUT_FILENO, ".", 1);
            }
        }

        // 3. Wait for Reply (Poll) with 10s Timeout [cite: 286-300]
        struct pollfd pfd;
        pfd.fd = sockfd;
        pfd.events = POLLIN;
        
        int ret = poll(&pfd, 1, TIMEOUT_MS);

        if (ret == 0) {
            // Timeout occurred - Terminate program as per instructions [cite: 58-59]
            printf("\nTimeout occurred! No reply received within 10 seconds. Terminating.\n");
            finish(0); 
        } else if (ret < 0) {
            perror("poll failed");
            finish(0);
        } else {
            // Data received
            if (pfd.revents & POLLIN) {
                struct sockaddr_in r_addr;
                socklen_t len = sizeof(r_addr);
                unsigned char buf[1024];

                int bytes = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&r_addr, &len);
                if (bytes > 0) {
                    struct iphdr *ip = (struct iphdr *)buf;
                    int iphdr_len = ip->ihl * 4;
                    struct icmphdr *icmp = (struct icmphdr *)(buf + iphdr_len);

                    // Check if it's an ECHO REPLY and if ID matches our PID
                    if (icmp->type == ICMP_ECHOREPLY && icmp->un.echo.id == htons(my_pid)) {
                        struct timeval sent_time, curr_time;
                        gettimeofday(&curr_time, NULL);
                        
                        // Extract original time from payload
                        unsigned char *payload_ptr = (unsigned char *)icmp + sizeof(struct icmphdr);
                        memcpy(&sent_time, payload_ptr, sizeof(sent_time));

                        double rtt = get_time_diff_ms(&sent_time, &curr_time);

                        // Update stats
                        if (rtt < rtt_min) rtt_min = rtt;
                        if (rtt > rtt_max) rtt_max = rtt;
                        rtt_sum += rtt;
                        rtt_sq_sum += (rtt * rtt);
                        packets_received++;
                        
                        int recv_seq = ntohs(icmp->un.echo.sequence);

                        // Print output
                        if (!flood_mode) {
                            printf("%d bytes from %s: icmp_seq=%d ttl=%d time=%.3f ms\n",
                                   bytes - iphdr_len, // ICMP packet size
                                   inet_ntoa(r_addr.sin_addr),
                                   recv_seq,
                                   ip->ttl,
                                   rtt);
                        } else {
                            write(STDOUT_FILENO, "\b", 1); // remove dot
                        }
                    }
                }
            }
        }

        // 4. Sleep 1 second (if not flood) [cite: 83]
        if (!flood_mode) {
            usleep(1000000); 
        }
        
        seq_counter++;
    }

    // End of loop - print final stats
    finish(0);
    return 0;
}