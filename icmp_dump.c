// ICMP DUMP by Bartosz Wasilewski
// wasilewski.b.j@gmail.com

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <net/if.h>

#define BUFFER_SIZE 0x10000	

int IcmpListen(char *interface);
int HexAsciiDump(unsigned char *buffer, int size); 

int main(int argc, char* argv[])
{
	if(argc < 2)
	{
		printf("Usage: %s <interface>\n", argv[0]);
		return 0;
	}
	else
	{
		return IcmpListen(argv[1]); // run sniffer
	}

	return 0;
}

// open socket, set interface, receive packets in loop
int IcmpListen(char *interface)
{
	// open socket
	int sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
	if(sockfd < 0)
	{
		printf("Socket error\n");
		return 1;
	}

	// set interface
	struct ifreq opt_ifr;
	memset(&opt_ifr, 0, sizeof(opt_ifr));
	snprintf(opt_ifr.ifr_name, sizeof(opt_ifr.ifr_name), interface); 
	int ret = setsockopt(sockfd, IPPROTO_ICMP, SO_BINDTODEVICE, (void*)&opt_ifr, sizeof(opt_ifr));
	if(ret < 0)
	{
		printf("Interface binding failed\n");
		return 1;
	}

	// allocate buffer memory
	unsigned char *buffer = (unsigned char*) malloc(BUFFER_SIZE);
	if(buffer == NULL)
	{
		printf("Buffer allocation failed\n");
		return 1;
	}

	// receive packets
	struct sockaddr src_addr;
	int src_addr_size = sizeof(src_addr);
	int data_size;
	while(1)
	{
		data_size = recvfrom(sockfd, buffer, BUFFER_SIZE, 0, &src_addr, &src_addr_size);
		if(data_size < 0)
		{
			printf("Failed to recieve packet\n");
			continue;
		}
		HexAsciiDump(buffer, data_size); // dump packet
	}
	
	close(sockfd);
	free(buffer);
	return 0;
}

// dump ICMP packet, format: [offset] [hex] [ascii]
int HexAsciiDump(unsigned char *buffer, int size )
{
	struct iphdr *header = (struct iphdr*) buffer;
	if(size > 0 && header->protocol == 1) // sanity check
	{ 
		int size_up = size + (0x10 - (size % 0x10)); // used for hex/ascii aligning
		int hexpass = 0; // hex/ascii print mode
		int i;
		for(i = 0; i <= size_up ; i++)
		{
			if(i % 0x10 == 0)
			{
				if(hexpass == 0)
				{
					if(i < size)
						printf("\n0x%02x%02x: ", i>>0x10, i); // print offset
					else
						break;
					hexpass = 1; // swap to hex
				}
				else
				{
					hexpass = 0;  // swap to ascii
					i -= 0x10;    // and go back
					printf("  ");
				}
			}
			
			if(hexpass == 1)
			{
				if(i % 2 == 0) 
					printf(" "); // group by 2 bytes
				if(i < size)
					printf("%02x", buffer[i]); // print in hex
				else
					printf("  "); // aligning
			}
			else
			{
				// print ascii
				if(i < size)
					printf("%c", buffer[i] >= ' ' && buffer[i] <= '~' ? buffer[i] : '.');
			}
		}
	}
	else
	{
		printf("Data invalid\n");
		return 1;
	}

	printf("\n");
	fflush(stdout);

	return 0;
}
