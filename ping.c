    #include <stdio.h>
    #include <stdlib.h>
    #include <unistd.h>
    #include <string.h>
    #include <sys/types.h>
    #include <sys/socket.h>
    #include <netinet/in.h>
    #include <netinet/ip_icmp.h>
    #include <arpa/inet.h>  // ensure this is included
    #include <time.h>
    #include <bits/getopt_core.h>
    #include <fcntl.h>
    #include <netdb.h>
    #include <netinet/ip.h>    // add this
    #include <sys/wait.h>
    #include <sys/time.h>
    #include <errno.h>


    #define PACKET_SIZE 64
    int pid=-1;
    int loops = 25;
    struct protoent *proto=NULL;
    struct hostent *hname=NULL;
    char* addr_str = NULL;
    int ping_count = 4;
    int flood_mode = 0;

    struct packet
    {
        struct icmphdr hdr;
        unsigned char msg[PACKET_SIZE];
        int msg_len;
    };

    typedef struct 
    {
        int seq;
        double rtt_ms;
    } packet_stats;



    unsigned short checksum(void *b, int len)
    {
        unsigned short *buf = b;
        unsigned int sum=0;
        unsigned short result;

        for ( sum = 0; len > 1; len -= 2 )
            sum += *buf++;
        if ( len == 1 )
            sum += *(unsigned char*)buf;
        sum = (sum >> 16) + (sum & 0xFFFF);
        sum += (sum >> 16);
        result = ~sum;
        return result;
    }

    packet_stats display(void *buf, int bytes)
    {
        packet_stats result = {0,0};
        struct iphdr *ip = (struct iphdr*)buf;
        int iphdr_len = ip->ihl * 4;

        if (bytes < iphdr_len + (int)sizeof(struct icmphdr)) return result;

        struct icmphdr *icmp = (struct icmphdr*)((unsigned char*)buf + iphdr_len);

        // filter: only replies to *our* ping
        if (icmp->type != ICMP_ECHOREPLY) return result;
        if (icmp->un.echo.id != (uint16_t)pid) return result;     
        // sequence is network byte order
        int seq = ntohs(icmp->un.echo.sequence);

        struct in_addr src;
        src.s_addr = ip->saddr;

        int ip_total  = ntohs(ip->tot_len);
        int payload = ip_total - iphdr_len - (int)sizeof(struct icmphdr);

        if (payload < (int)sizeof(struct timeval)) return result;

        unsigned char *icmp_payload = (unsigned char*)icmp + sizeof(struct icmphdr);

        struct timeval sent, now;
        memcpy(&sent, icmp_payload, sizeof(sent));
        gettimeofday(&now, NULL);

        double rtt_ms =
            (now.tv_sec - sent.tv_sec) * 1000.0 +
            (now.tv_usec - sent.tv_usec) / 1000.0;


        memcpy(&sent, icmp_payload, sizeof(sent));
        gettimeofday(&now, NULL);
        printf("%d bytes from %s icmp_seq=%d ttl=%d time=%.2fms\n",
            payload, inet_ntoa(src), seq, ip->ttl, rtt_ms);
        
        result.rtt_ms=rtt_ms;
        result.seq=seq;
        return result;
    }

    void dispaly_stats(double* rtts, int recived)
    {
        double max=rtts[0], min=rtts[0];
        double sum=0;
        int count=0;
        for(int i=0;i<ping_count;i++)
        {
            if(rtts[i]>=0)
            {
                if(rtts[i]>max) max=rtts[i];
                if(rtts[i]<min) min=rtts[i];
                sum+=rtts[i];
                count++;            
            }
        }
        printf("\n--- %s ping statistics ---\n", addr_str);
        printf("%d packets transmitted %d packets received time %.2fms\n",
            ping_count, recived,
            sum);
        
        if(count>0)
        {
            printf("rtt min/avg/max = %.2f/%.2f/%.2f ms\n",
                min, sum/(double)count, max);
        }        
    }


    void listen_for_replies(void)
{
    struct sockaddr_in r_addr;
    unsigned char buf[1024];

    int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (sockfd < 0) { perror("Socket creation failed"); return; }
    int recived=0;
    double rtts[ping_count];
    for (int expected = 1; expected <= ping_count; expected++)
    {
        int got = 0;

        while (!got)
        {
            fd_set rfds;
            FD_ZERO(&rfds);
            FD_SET(sockfd, &rfds);

            struct timeval tv;
            tv.tv_sec = 1;    
            tv.tv_usec = 0;

            int rc = select(sockfd + 1, &rfds, NULL, NULL, &tv);
            if (rc == 0) {
                // timeout
                printf("Request timeout for icmp_seq %d\n", expected);
                rtts[expected - 1] = -1;
                break;
            }
            if (rc < 0) {
                perror("select");
                close(sockfd);
                return;
            }

            socklen_t len = sizeof(r_addr);
            int bytes = recvfrom(sockfd, buf, sizeof(buf), 0,
                                 (struct sockaddr*)&r_addr, &len);
            if (bytes < 0) {
                if (errno == EINTR) continue;
                perror("recvfrom");
                break;
            }
            
            packet_stats stats = display(buf, bytes);
            
            if (stats.seq == expected) {
                got = 1; 
                recived++;  
                rtts[stats.seq - 1] = stats.rtt_ms;
            }
        }
    }
    dispaly_stats(rtts, recived);
    close(sockfd);
}

    int ping(struct sockaddr_in *addr, int count, int flood)
    {
        struct sockaddr_in r_addr;
        struct packet pckt;

        int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
        if (sockfd < 0)
        {
            perror("Socket creation failed");
            return -1;
        }
        //if(setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &(int){1}, sizeof(int)) < 0)
        //{
        //    perror("Set socket options failed");
        //    close(sockfd);
        //    return -1;
        //}
        if(fcntl(sockfd, F_SETFL, O_NONBLOCK) < 0)
        {
            perror("Set socket non-blocking failed");
            close(sockfd);
            return -1;
        }
        printf("Pinging %s with %d bytes of data:\n", addr_str, PACKET_SIZE);
        for(int i = 0; i < count; i++)
        {
            memset(&pckt, 0, sizeof(pckt));
            pckt.hdr.type = ICMP_ECHO;
            pckt.hdr.un.echo.id = pid;
            pckt.hdr.un.echo.sequence = htons(i + 1);
            struct timeval t;
            gettimeofday(&t, NULL);
            memcpy(pckt.msg, &t, sizeof(t));
            pckt.hdr.checksum = 0;
            pckt.hdr.checksum = checksum(&pckt, sizeof(pckt));

            struct sockaddr_in addr_con;
            addr_con.sin_family = AF_INET;
            addr_con.sin_addr.s_addr = inet_addr(addr_str);

            char ipstr[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &addr->sin_addr, ipstr, sizeof(ipstr));
            
            if (sendto(sockfd, &pckt, sizeof(pckt), 0,
                    (struct sockaddr*)addr, sizeof(*addr)) <= 0) {
                perror("Packet send failed");
            } else {
                if (flood) write(STDOUT_FILENO, ".", 1);
            }

            if(!flood)
                usleep(1000000); // Sleep for 1 second
        }
        
        return 0;
    }

    int main(int argc, char *argv[])
    {
        struct hostent *hname;
        struct sockaddr_in addr;

        int opt;
        while ((opt=getopt(argc,argv,"a:c:f"))!=-1)
        {
            switch (opt)
            {
            case 'a':
                addr_str = optarg;
                break;
            case 'c':
                ping_count = atoi(optarg);
                break;
            case 'f':
                flood_mode  = 1;
                break;
            
            default:
                break;
            }
        }
        if ( ping_count > 1 ) 
        {
            pid = getpid();
            proto = getprotobyname("ICMP");
            hname = addr_str ? gethostbyname(addr_str) : NULL;
            bzero(&addr, sizeof(addr));
            addr.sin_family = AF_INET;
            addr.sin_port = 0;
            memcpy(&addr.sin_addr, hname->h_addr_list[0], hname->h_length);
            if (fork() == 0) 
            {
                listen_for_replies();
            } 
            else 
            {
                usleep(200000); // 200ms - give child time to start listening
                ping(&addr, ping_count, flood_mode);
            }
            wait(0);
        }
        return 0;
    }