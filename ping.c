#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netdb.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <sys/select.h>

#define PACKET_LEN_DEFAULT_NUM 56
static uint16_t seq = 1;

static uint16_t icmp_checksum(void* b, int len);
static unsigned short ip_checksum(unsigned short* buff, int _16bitword);


int main(int argc, char* argv[])
{
    int send_sock, recv_sock;
    int err;
    size_t data_len = PACKET_LEN_DEFAULT_NUM;
    size_t total_len = 0;

    const char* args = argv[1];
    unsigned char* packet;

    struct sockaddr_in dest;
    struct sockaddr_in rep_addr;
    socklen_t rep_len = sizeof(rep_addr);

    struct iphdr* iph;
    struct icmphdr* icmph;

    if (argc < 2)
    {
	fprintf(stderr, "Usage: %s <host>\n", argv[0]);
	exit(1);
    }

    packet = malloc(data_len);
    if (!packet)
    {
	fprintf(stderr, "malloc: packet\n");
	exit(1);
    }

    dest.sin_family = AF_INET;
    dest.sin_port = 0;

    if (inet_pton(AF_INET, args, &dest.sin_addr) <= 0)
    {
	fprintf(stderr, "inet_pton");
	exit(1);
    }

    iph = (struct iphdr*) packet; 

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 16;
    iph->id = htons(getpid() & 0xFFFF);
    iph->ttl = 64;
    iph->protocol = 1;
    iph->saddr = inet_addr("10.85.53.148");
    iph->daddr = dest.sin_addr.s_addr;

    total_len += sizeof(struct iphdr);

    icmph = (struct icmphdr*) (packet + sizeof(struct iphdr));

    icmph->type = 8;
    icmph->code = 0;
    icmph->un.echo.id = getpid() & 0xFFFF;

    total_len += sizeof(struct icmphdr);

    packet[total_len++] = 0xAA;
    packet[total_len++] = 0xBB;
    packet[total_len++] = 0xCC;
    packet[total_len++] = 0xEE;

    iph->tot_len = htons(total_len);
    iph->check = ip_checksum((unsigned short*)iph, sizeof(struct iphdr)/2);

    send_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    recv_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    if (send_sock < 0 || recv_sock < 0)
    {
	fprintf(stderr, "socket\n");
	exit(1);
    }

    int one = 1;

    if(setsockopt(send_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0)
    {
	fprintf(stderr, "setsockopt IP_HDRINCL\n");
	exit(1);
    }

    ssize_t send_len = 0;
    ssize_t reply_len = 0;
    char rep_buffer[1024];

    while (1)
    {
	icmph->un.echo.sequence = seq++;
	icmph->checksum = 0;
	icmph->checksum = icmp_checksum(icmph, sizeof(struct iphdr) + 4); 
	struct timeval tv, start, end;

	int ret;

	fd_set fds;
	FD_ZERO(&fds);
	FD_SET(recv_sock, &fds);
	tv.tv_sec = 1;
	tv.tv_usec = 0;

	gettimeofday(&start, NULL);

	err = send_len = sendto(send_sock, packet, total_len, 0, (const struct sockaddr*)&dest, sizeof(struct sockaddr_in));

	if (err < 0)
	{
	    fprintf(stderr, "Sending error: sendlen = %zd, err = %d\n", send_len, err);
	    return -1;
	}

	ret = select(recv_sock + 1, &fds, NULL, NULL, &tv);

	if (ret > 0)
	{
	
	    err = reply_len = recvfrom(recv_sock, rep_buffer, sizeof(rep_buffer), 0, (struct sockaddr*)&rep_addr, &rep_len);

	    if (reply_len < 0)
		continue;

	    gettimeofday(&end, NULL);

	    long rtts_ms = (end.tv_sec - start.tv_sec) * 1000 + (end.tv_usec - start.tv_usec) / 1000;

	    struct iphdr* ip_rep = (struct iphdr*)rep_buffer;
	    int ip_rep_len = ip_rep->ihl * 4;
    
	    struct icmphdr* icmp_rep = (struct icmphdr*)(rep_buffer + ip_rep_len);

	    if (icmp_rep->type == ICMP_ECHOREPLY &&
		    icmp_rep->un.echo.id == (getpid() & 0xFFFF))
	    {
		printf("%zd bytes from %s: seq=%d ttl= %d time=%ld ms\n",reply_len, inet_ntoa(rep_addr.sin_addr), icmp_rep->un.echo.sequence, ip_rep->ttl, rtts_ms);
	    }

	}
	else if(ret == 0)
	{
	    fprintf(stderr, "time-out: packets were not received\n");
	    return -1;
	}
	else
	{
	    perror("select");
	    exit(1);
	}

	sleep(1);

    }
    
    free(packet);
    close(send_sock);
    close(recv_sock);
    return err;
}

static uint16_t icmp_checksum(void* b, int len)
{
    uint16_t* buf = b;
    unsigned int sum = 0;

    while(len > 1)
    {
	sum += *buf++;
	len -= 2;
    }

    if (len == 1)
    {
	sum += * (unsigned char*)buf;
    }

    while (sum >> 16)
    {
	sum = (sum & 0xFFFF) + (sum >> 16);
    }

    return (uint16_t)(~sum);
}

static unsigned short ip_checksum(unsigned short* buff, int _16bitword)
{
    unsigned long sum;

    for (sum = 0; _16bitword > 0; _16bitword--)
    {
	sum += htons(*(buff)++);
	sum = ((sum >> 16) + (sum & 0xFFFF));
	sum += (sum >> 16);
    }
    
    return (unsigned short)(~sum);
}

