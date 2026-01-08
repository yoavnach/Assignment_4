#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <poll.h>
#include <errno.h>
#include <pthread.h>

#define SLEEP_USEC 5000 // 5 milliseconds
#define MAX_PORT 65536
#define MIN_PORT 1

struct scan_config {
    const char* ip;
    int sockfd;
    uint32_t src_ip;
};
struct pseudo_header {
    u_int32_t source_address;
    u_int32_t dest_address;
    u_int8_t placeholder;
    u_int8_t protocol;
    u_int16_t length;
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

uint32_t get_local_ip() {
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in serv;
    memset(&serv, 0, sizeof(serv));
    serv.sin_family = AF_INET;
    serv.sin_addr.s_addr = inet_addr("8.8.8.8");
    serv.sin_port = htons(53);
    connect(sock, (const struct sockaddr*)&serv, sizeof(serv));
    struct sockaddr_in name;
    socklen_t namelen = sizeof(name);
    getsockname(sock, (struct sockaddr*)&name, &namelen);
    close(sock);
    return name.sin_addr.s_addr;
}

void* listen_icmp(void* arg) {
    struct scan_config* config = (struct scan_config*)arg;
    unsigned char buf[4096];
    
    while (1) {
        int bytes = recvfrom(config->sockfd, buf, sizeof(buf), 0, NULL, NULL);
        if (bytes < 0) continue;

        struct iphdr *recv_ip = (struct iphdr *)buf;
        if (recv_ip->protocol != IPPROTO_TCP) continue;

        struct tcphdr *recv_tcp = (struct tcphdr *)(buf + (recv_ip->ihl * 4));

        // בדיקה שהתשובה מיועדת לפורט המקור שלנו ושהיא SYN-ACK
        if (recv_tcp->dest == htons(12345)) {
            if (recv_tcp->syn == 1 && recv_tcp->ack == 1) {
                printf("Port %d: Open\n", ntohs(recv_tcp->source));
            }
        }
    }
    return NULL;
}
void* listen_udp_responses(void* arg) {
    struct scan_config* config = (struct scan_config*)arg;
    int udp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    unsigned char buf[1024];

    while (1) {
        struct sockaddr_in from;
        socklen_t fromlen = sizeof(from);
        int bytes = recvfrom(udp_sock, buf, sizeof(buf), 0, (struct sockaddr*)&from, &fromlen);
        
        if (bytes < 0) continue;

        struct iphdr *iph = (struct iphdr *)buf;
        // בדיקה שהתגובה מגיעה מה-IP שסרקנו
        if (iph->saddr != inet_addr(config->ip)) continue;

        struct udphdr *udph = (struct udphdr *)(buf + (iph->ihl * 4));

        // אם היעד שלח חבילה חזרה לפורט המקור שלנו (12345)
        if (ntohs(udph->dest) == 12345) {
            int open_port = ntohs(udph->source); // הפורט שסרקנו ביעד
            if (open_port >= 0 && open_port < MAX_PORT) {
                printf("Port %d: Open (UDP Response)\n", open_port);
            }
        }
    }
    return NULL;
}

void* scan_tcp(void* arg) {
    struct scan_config* config = (struct scan_config*)arg;
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) { perror("Socket failed"); return NULL; }
    const char* dest_ip_str = config->ip;
    int start_port = MIN_PORT;
    int end_port = MAX_PORT;
    int on = 1;
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(dest_ip_str);

    uint32_t src_ip = get_local_ip();

    printf("Starting TCP Scan on %s...\n", dest_ip_str);

    for (int port = start_port; port <= end_port; port++) {
        char packet[4096];
        memset(packet, 0, sizeof(packet));

        struct iphdr *iph = (struct iphdr *)packet;
        struct tcphdr *tcph = (struct tcphdr *)(packet + sizeof(struct iphdr));
        struct pseudo_header psh;

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr);
        iph->id = htons(54321);
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_TCP;
        iph->saddr = src_ip;
        iph->daddr = dest.sin_addr.s_addr;
        iph->check = checksum((unsigned short *)packet, iph->tot_len);

        tcph->source = htons(12345);
        tcph->dest = htons(port);
        tcph->seq = 0;
        tcph->ack_seq = 0;
        tcph->doff = 5;
        tcph->fin = 0;
        tcph->syn = 1;
        tcph->rst = 0;
        tcph->psh = 0;
        tcph->ack = 0;
        tcph->urg = 0;
        tcph->window = htons(5840);
        tcph->check = 0;
        tcph->urg_ptr = 0;

        psh.source_address = src_ip;
        psh.dest_address = dest.sin_addr.s_addr;
        psh.placeholder = 0;
        psh.protocol = IPPROTO_TCP;
        psh.length = htons(sizeof(struct tcphdr));

        int psize = sizeof(struct pseudo_header) + sizeof(struct tcphdr);
        char *pseudogram = malloc(psize);
        memcpy(pseudogram, (char*)&psh, sizeof(struct pseudo_header));
        memcpy(pseudogram + sizeof(struct pseudo_header), tcph, sizeof(struct tcphdr));
        tcph->check = checksum((unsigned short*)pseudogram, psize);
        free(pseudogram);

        if (sendto(sockfd, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            continue;
        }
        usleep(SLEEP_USEC); //to avoid flooding the network wait for 5 milliseconds
       
    }
    
    return NULL;
}

void* scan_udp(void* arg) {
    struct scan_config* config = (struct scan_config*)arg;
    int sock_send = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    int sock_icmp = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    const char* dest_ip_str = config->ip;
     int start_port = MIN_PORT;
      int end_port = MAX_PORT;

    int on = 1;
    if (setsockopt(sock_send, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("setsockopt IP_HDRINCL");
        close(sock_send);
        close(sock_icmp);
        return NULL;
    }

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_addr.s_addr = inet_addr(dest_ip_str);

    uint32_t src_ip = get_local_ip();

    printf("Starting UDP Scan on %s...\n", dest_ip_str);

    for (int port = start_port; port <= end_port; port++) {
        char packet[4096];
        memset(packet, 0, sizeof(packet));

        struct iphdr *iph = (struct iphdr *)packet;
        struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));

        iph->ihl = 5;
        iph->version = 4;
        iph->tos = 0;
        iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr));
        iph->id = 0;
        iph->frag_off = 0;
        iph->ttl = 64;
        iph->protocol = IPPROTO_UDP;
        iph->saddr = src_ip;
        iph->daddr = dest.sin_addr.s_addr;
        iph->check = 0;
        iph->check = checksum((unsigned short *)iph, sizeof(struct iphdr));

        udph->source = htons(12345);
        udph->dest   = htons(port);
        udph->len    = htons(sizeof(struct udphdr));
        udph->check  = 0; // IPv4 UDP checksum יכול להיות 0

        if (sendto(sock_send, packet, sizeof(struct iphdr) + sizeof(struct udphdr),
                   0, (struct sockaddr *)&dest, sizeof(dest)) < 0) {
            perror("sendto failed");
            if(errno == EPERM) {
                printf("Run the program with sudo/root privileges.\n");
                close(sock_send);
                close(sock_icmp);
                return NULL;
            }
            if(errno == ENOBUFS) {
                usleep(SLEEP_USEC*2); // לחכות מעט ולנסות שוב
                port--; // לנסות את אותו הפורט שוב
                continue;
            }
            if(errno == EHOSTUNREACH) {
                printf("Host unreachable. Stopping scan.\n");
                break;
            }
        }
        (void)sendto(sock_send, packet, sizeof(struct iphdr) + sizeof(struct udphdr),
                     0, (struct sockaddr *)&dest, sizeof(dest));

        usleep(SLEEP_USEC); //to avoid flooding the network wait for 5 milliseconds
    }

    close(sock_send);
    close(sock_icmp);
    return NULL;
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: sudo %s -a <ip> -t <type>\n", argv[0]);
        return 1;
    }
    
    char *ip = argv[2];
    char *type = argv[4];

    

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) {
        perror("Socket creation failed");
        exit(1);
    }
    struct scan_config config = {ip, sockfd, get_local_ip()};
    int on = 1;
    if (setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on)) < 0) {
        perror("Error setting IP_HDRINCL");
        exit(1);
    }
    pthread_t send_thread, recv_thread;
    if (strcmp(type, "TCP") == 0) {
        
        pthread_create(&recv_thread, NULL, listen_icmp, &config);
        pthread_create(&send_thread, NULL, scan_tcp, &config); 
    } else if (strcmp(type, "UDP") == 0) {
        pthread_create(&recv_thread, NULL, listen_udp_responses, &config);
        pthread_create(&send_thread, NULL, scan_udp, &config); 
    } else {
        printf("Invalid type. Use TCP or UDP.\n");
    }
    
    pthread_join(send_thread, NULL);
    printf("Waiting for final responses...\n");
    sleep(2);
    pthread_cancel(recv_thread);
    close(sockfd);
    return 0;
}