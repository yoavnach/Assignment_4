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

#define TIMEOUT_MS 200

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

void scan_tcp(const char* dest_ip_str, int start_port, int end_port) {
    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sockfd < 0) { perror("Socket failed"); return; }

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

        struct pollfd pfd;
        pfd.fd = sockfd;
        pfd.events = POLLIN;
        if (poll(&pfd, 1, TIMEOUT_MS) > 0) {
            unsigned char buf[4096];
            struct sockaddr_in r_addr;
            socklen_t len = sizeof(r_addr);
            int bytes = recvfrom(sockfd, buf, sizeof(buf), 0, (struct sockaddr *)&r_addr, &len);
            
            if (bytes > 0) {
                struct iphdr *recv_ip = (struct iphdr *)buf;
                struct tcphdr *recv_tcp = (struct tcphdr *)(buf + (recv_ip->ihl * 4));
                
                if (recv_ip->saddr == dest.sin_addr.s_addr && recv_tcp->dest == htons(12345)) {
                    if (recv_tcp->syn == 1 && recv_tcp->ack == 1) {
                        printf("Port %d: Open\n", port);
                        
                        tcph->syn = 0;
                        tcph->rst = 1;
                        tcph->seq = recv_tcp->ack_seq;
                        sendto(sockfd, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest));
                    }
                }
            }
        }
    }
    close(sockfd);
}

void scan_udp(const char* dest_ip_str, int start_port, int end_port) {
    int sock_send = socket(AF_INET, SOCK_RAW, IPPROTO_UDP);
    int sock_recv = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    
    if (sock_send < 0 || sock_recv < 0) { perror("Socket failed"); return; }
    
    int on = 1;
    setsockopt(sock_send, IPPROTO_IP, IP_HDRINCL, &on, sizeof(on));

    struct sockaddr_in dest;
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
        iph->tot_len = sizeof(struct iphdr) + sizeof(struct udphdr);
        iph->ttl = 64;
        iph->protocol = IPPROTO_UDP;
        iph->saddr = src_ip;
        iph->daddr = dest.sin_addr.s_addr;
        iph->check = checksum((unsigned short *)packet, iph->tot_len);

        udph->source = htons(12345);
        udph->dest = htons(port);
        udph->len = htons(sizeof(struct udphdr));
        udph->check = 0;

        sendto(sock_send, packet, iph->tot_len, 0, (struct sockaddr *)&dest, sizeof(dest));

        struct pollfd pfd;
        pfd.fd = sock_recv;
        pfd.events = POLLIN;
        
        if (poll(&pfd, 1, TIMEOUT_MS) > 0) {
            unsigned char buf[4096];
            struct sockaddr_in r_addr;
            socklen_t len = sizeof(r_addr);
            recvfrom(sock_recv, buf, sizeof(buf), 0, (struct sockaddr *)&r_addr, &len);
            
            struct iphdr *rip = (struct iphdr *)buf;
            struct icmphdr *ricmp = (struct icmphdr *)(buf + (rip->ihl * 4));
            
            if (rip->saddr == dest.sin_addr.s_addr && ricmp->type == ICMP_DEST_UNREACH && ricmp->code == 3) {
                 // Closed
            } else {
                 // Maybe open
            }
        }
    }
    close(sock_send);
    close(sock_recv);
}

int main(int argc, char *argv[]) {
    if (argc != 5) {
        printf("Usage: sudo %s -a <ip> -t <type>\n", argv[0]);
        return 1;
    }
    
    char *ip = argv[2];
    char *type = argv[4];

    if (strcmp(type, "TCP") == 0) {
        scan_tcp(ip, 1, 65535); 
    } else if (strcmp(type, "UDP") == 0) {
        scan_udp(ip, 1, 65535);
    } else {
        printf("Invalid type. Use TCP or UDP.\n");
    }

    return 0;
}





