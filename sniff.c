#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

// libpcap descriptor. The pcap socket descriptor is a pcap_t pointer to a structure identifies the packet capture channel and used in all libpcap functions.
pcap_t* pd;

// link header size. used during packet capture and parsing to skip over the datalink layer header to get to the IP header of each packet.
int link_header_size;

pcap_t* open_pcap_socket( char* device, const char* bpfstr ) 
{
	char errBuf[ PCAP_ERRBUF_SIZE ];
	pcap_t* pd;
	uint32_t srcip, netmask;
	struct bpf_program bpf;

	// If no network interface (device ) is specified, get the first one using pcap_lookup().
	if ( !*device && !( device == pcap_lookupdev( errBuf ) ) ) 
	{
		printf("\npcap_lookupdev(): %s\n", errBuf );
		return NULL;
	}
	
	// Open the network interface (device) for live capture, as opposed to reading a packet capture file.
	if ( (pd = pcap_open_live( device, BUFSIZ, 1, 0, errBuf )) == NULL ) 
	{
		printf("pcap_open_live(): %s\n", errBuf );
		return NULL;
	}

	// Get network device source IP address and netmask.
	if ( pcap_lookupnet( device, &srcip, &netmask, errBuf ) < 0 ) 
  	{
		printf("pcap_lookupnet: %s\n", errBuf );
		return NULL;
	}
	
	// Convert the packet filter expression into a packet filter binary.
	if ( pcap_compile( pd, &bpf, (char*)bpfstr, 0, netmask )) 
	{
		printf("pcap_compile(): %s\n", pcap_geterr(pd));
		return NULL;
	}

	// Assign the packet filter to given libpcap socket.
	if( pcap_setfilter(pd, &bpf) < 0 ) 
	{
		printf("pcap_setfilter(): %s\n", pcap_geterr(pd));
		return NULL;
	}

	return pd;
}


void capture_loop( pcap_t* pd, int packets, pcap_handler func )
{
	int linktype;
	
	// Determine the datalink layer type.
	if( (linktype = pcap_datalink( pd ) ) < 0 )
	{
		printf("pcap_datalink(): %s\n",pcap_geterr( pd ) );
		return;
	}

	// Set the datalink layer header size.
	switch( linktype )
	{
		case DLT_NULL:
			link_header_size = 4;
			break;

		case DLT_EN10MB:
			link_header_size = 14;
			break;
			
		case DLT_SLIP:
		case DLT_PPP:
			link_header_size = 24;
			break;

		default:
			printf("Unsupported data link (%d)\n", linktype );
			return;
	}

	// start capturing packets
	if( pcap_loop( pd, packets, func, 0 ) < 0 )
	{
		printf("pcap_loop failed: %s\n", pcap_geterr( pd ) );
	}
}


void parse_packet( u_char *user, struct pcap_pkthdr *packethdr, u_char *packetptr )
{
	struct ip* iphdr;
	struct icmphdr* icmphdr;
	struct tcphdr* tcphdr;
	struct udphdr* udphdr;
	char iphdrInfo[256], srcip[256], destip[256];
	unsigned short id, seq;
	
	// Skip the datalink layer header and get the IP header fields.
	packetptr += link_header_size;
	iphdr = (struct ip*)packetptr;
	strcpy( srcip, inet_ntoa( iphdr->ip_src ) );
	strcpy( destip, inet_ntoa( iphdr->ip_dst ) );
	sprintf( iphdrInfo, "ID: %d TOS: 0x%x, TTL: %d IpLen: %d DgLen:%d", 
		ntohs( iphdr->ip_id ), iphdr->ip_tos, iphdr->ip_ttl, 4*iphdr->ip_hl, ntohs( iphdr->ip_len) );
	
	// Advance to the transport layer header then parse and display the fields based 
	// on the type of header : tcp/udp/icmp
	
	packetptr += 4*iphdr->ip_hl;
	switch( iphdr->ip_p )
	{
		case IPPROTO_TCP:
			tcphdr = ( struct tcphdr* )packetptr;
			printf("TCP	%s:%d -> %s:%d\n", srcip, ntohs( tcphdr->source), 
						destip, ntohs( tcphdr->dest ) );
			printf("%s\n", iphdrInfo);
			printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
				(tcphdr->urg ? 'U' : '*'),
				(tcphdr->ack ? 'A' : '*'),
				(tcphdr->psh ? 'P' : '*'),
				(tcphdr->rst ? 'R' : '*'),
				(tcphdr->syn ? 'S' : '*'),
				(tcphdr->fin ? 'F' : '*'),
				ntohl( tcphdr->seq ), ntohl( tcphdr->ack_seq ), 
				ntohl( tcphdr->window ), 4*tcphdr->doff );
			break;
		
		case IPPROTO_UDP:
			udphdr = (struct udphdr* )packetptr;
			printf("UDP	%s:%d -> %s:%d\n", srcip, ntohs( udphdr->source ), 
						destip, ntohs( udphdr->dest ) );
			printf("%s\n", iphdrInfo );
			break;
		
		case IPPROTO_ICMP:
			icmphdr = (struct icmphdr*)packetptr;
			printf("ICMP %s -> %s\n", srcip, destip );
			printf("%s\n", iphdrInfo );
			memcpy( &id, (u_char*)icmphdr+4, 2 );
			memcpy( &seq, (u_char*)icmphdr+6, 2);
			printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->type, icmphdr->code,
					ntohs( id ) , ntohs( seq ) );
			break;
		}
		
		printf("________________________x__________________x_____________________x\n\n");
}


void bailout( int signo )
{
	struct pcap_stat stats;
	
	if( pcap_stats( pd, &stats ) >= 0 )
	{
		printf("%d packets received\n", stats.ps_recv );
		printf("%d packets dropped\n\n", stats.ps_drop );
	}
	pcap_close( pd );
	exit(0);
}


int main( int argc, char **argv ) 
{
	char interface[256] = "", bpfstr[256] = "";
	int packets = 0, c, i;
	
	// Get the cmd line options if any 
	while( ( c = getopt( argc, argv, "hi:n:" ) ) != -1 )
	{
		switch( c )
		{
			case 'h':
				printf("usage:	%s [-h] [-i] []\n", argv[0] );
				exit(0);
				break;
			case 'i':
				strcpy( interface, optarg );
				break;
			case 'n':
				packets = atoi( optarg );
				break;
		}
	}
	
	// Get the packet capture filter expression, if any.
	for ( i = optind; i < argc; i++ )
	{
		strcat( bpfstr, argv[i] );
		strcat( bpfstr, " " );
	}
	
	// Open libpcap, set the program termination signals then start
	// processing of packets
	if ( (pd = open_pcap_socket( interface, bpfstr ))) 
	{
		signal( SIGINT, bailout );
		signal( SIGTERM, bailout );
		signal( SIGQUIT, bailout );
		capture_loop( pd, packets, (pcap_handler)parse_packet);
		bailout(0);
	}
	exit(0);
}
	

