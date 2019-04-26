
/*-
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
//### decoder Hash Table is done! ready for test 26032019###################### 
//### Today 15March2019: we are trying to include hash table in it ############  
//### Name of file: main_dec_27March2018.cpp ################################## 
//#####################edited at 10sep#########################################
#include "/home/waqas/Downloads/libRaptorQ-0.1.7/src/cRaptorQ.h"
//#include "/home/ahmed/libRaptorQ-0.1.7/src/cRaptorQ.h"
#include <stdbool.h>
#include <signal.h>
#include <stdlib.h>
#include <rte_igmp.h>
#include <time.h>
#include <math.h>
//##############################//
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/queue.h>

#include <rte_memory.h>
#include <rte_memzone.h>
#include <rte_launch.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_lcore.h>
#include <rte_debug.h>
#include <rte_common.h>
#include <rte_vect.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_malloc.h>
#include <rte_memzone.h>
#include <rte_eal.h>
#include <rte_per_lcore.h>
#include <rte_launch.h>
#include <rte_atomic.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_lcore.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_pci.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_ring.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_rtp.h>
#include <rte_fec.h>
#include <rte_timer.h>
#include <list>
#include <string.h>
#include <getopt.h>
#include <rte_hash.h>
#include <rte_hash_crc.h>
#define DEFAULT_HASH_FUNC       rte_hash_crc

#define RTP 0
#define FEC 1
#define OTHER 2
#define IGMP 3
static volatile bool force_quit;
//#define L 6
//#define D 4
int L = 0, D = 0;
uint32_t oti_scheme = 0;
uint64_t oti_common = 0;
uint32_t groupAdd = 0;
/*
 * Construct Ethernet multicast address from IPv4 multicast address.
 * Citing RFC 1112, section 6.4:
 * "An IP host group address is mapped to an Ethernet multicast address
 * by placing the low-order 23-bits of the IP address into the low-order
 * 23 bits of the Ethernet multicast address 01-00-5E-00-00-00 (hex)."
 */
#define	ETHER_ADDR_FOR_IPV4_MCAST(x)	\
	(rte_cpu_to_be_64(0x01005e000000ULL | ((x) & 0x7fffff)) >> 16)
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
bool packetMbufsSource(struct rte_mbuf **, int );
void constRtpPacket(struct rte_mbuf *, uint32_t, uint16_t, uint32_t );
uint8_t getProtocol( struct rte_mbuf * );
uint32_t getDestinationIp( struct rte_mbuf * );
uint32_t getSourceIp( struct rte_mbuf * );
static void printStats();
uint8_t packetType( struct rte_mbuf * );
bool igmpPacket(struct rte_mbuf * );
#define NB_MBUF             (8192*2*2*2)
#define MAX_PKT_BURST       32
#define NB_SOCKETS          0
#define MEMPOOL_CACHE_SIZE  256
#define NUM_OF_LCORES 4

#define BOND_IP_1       1
#define BOND_IP_2       1
#define BOND_IP_3       1
#define BOND_IP_4       10

#define BOND_IP1_1       13
#define BOND_IP1_2       6
#define BOND_IP1_3       53
#define BOND_IP1_4       225
#define NMSOCKET    2
#define BASETS 32
 
static struct ether_addr ports_eth_addr[2];  // defined already RTE_MAX_ETHPORTS = 32
uint32_t multiCastIp = 0;    // no use
bool MarkCopy[65536][2];     // no use 
uint32_t *table1 = NULL;     // no use
uint32_t igmpSourceIp = 0;   
struct lcore_para
{
	struct rte_ring *worker_rx;
	struct rte_ring *worker_tx;
	int missed_x;
	int missed_y;
};
struct SourceGroup
{
	uint32_t multiCastIp;
    uint32_t sourceIp;
	uint32_t synSource;
    uint16_t udpDestPort;
    uint16_t udpSrcPort;
	struct ether_addr mc_eth_addr[2];
	bool set;
}NewAddresses[8];
int packetMiss = 0;
uint32_t TS = 3333;
uint16_t snn = 0;
struct iState
{
	int ID;        // record id  
	uint8_t port;
	uint32_t groupAddress;
	std::list <uint32_t> source_list_include;
	std::list <uint32_t> source_list_exclude;
	//static struct rte_timer gen;  
};
std::list<struct iState> InterfaceState;
static struct rte_timer gen[10];
struct MarkDataSymbols
{
	bool Mark;
	struct rte_mbuf *pkt; 
};
struct MarkFecSymbols
{
	bool Mark;
	struct rte_mbuf *pkt; 
};
struct blockIndex
{
	int startIndex;
	int endIndex;
};
struct tsrecovery
{
	uint16_t seq_number;
	uint32_t time_stamp;
	uint32_t ts_difference;
	uint32_t pTime_stamp;
	uint32_t counter;
	
};
struct tsrecovery tsr;
/*
 * Configurable number of RX/TX ring descriptors
 */
#define RTE_TEST_RX_DESC_DEFAULT 128
#define RTE_TEST_TX_DESC_DEFAULT 512
static uint16_t nb_rxd = RTE_TEST_RX_DESC_DEFAULT;
static uint16_t nb_txd = RTE_TEST_TX_DESC_DEFAULT;
static struct rte_mempool *pktmbuf_pool[NMSOCKET];

void gotoxy(int, int);
static void print_ethaddr(const char *name, const struct ether_addr *eth_addr)
{
	char buf[ETHER_ADDR_FMT_SIZE];
	ether_format_addr(buf, ETHER_ADDR_FMT_SIZE, eth_addr);
	printf("%s%s", name, buf);
}

static int
init_mem(unsigned nb_mbuf)
{
	int socketid = 0;
	pktmbuf_pool[0] =  rte_pktmbuf_pool_create("MBUF2-POOL2", nb_mbuf,
					                    MEMPOOL_CACHE_SIZE, 0,
					                    RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
			if (pktmbuf_pool[0] == NULL)
				rte_exit(EXIT_FAILURE,"Cannot init mbuf pool on socket %d\n", socketid);
			else
				printf("Allocated mbuf pool on socket %d\n", socketid);
	
	// NOTE: Calling rte_malloc here will result in mbuf allocation fail...?
	/* allocating memory area for 50 symbols, 128 byte each */ 
	/*
		table1 = (uint32_t *)rte_malloc(NULL, sizeof(uint8_t) * 128 * 50, 32); 

		uint32_t *temp = table1;
		for(  int x=0; x<(128*50); x++   )
			temp[x] = 0;
	*/
	return 0;

}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
//              				HASH STRUCTS FUNCTIONS
void populate_hash_table_with_multicast_add(void);
struct ipv4_5tuple {
        uint32_t ip_dst;
        uint32_t ip_src;
        uint16_t port_dst;
        uint16_t port_src;
        uint8_t  proto;
} __attribute__((__packed__));

struct ipv4_l3fwd_route {
	struct ipv4_5tuple key;
	uint8_t if_out;
};

static struct ipv4_l3fwd_route ipv4_l3fwd_route_array[] = 
{
	{{IPv4(225,53,6,13), IPv4(10,177,6,13),  8234, 1234, IPPROTO_UDP}, 0},
	{{IPv4(227,2,3,4), IPv4(200,20,0,1),  102, 12, IPPROTO_TCP}, 1},
	{{IPv4(229,1,1,1), IPv4(100,30,0,1),  101, 11, IPPROTO_TCP}, 2},
	{{IPv4(231,1,2,8), IPv4(200,80,0,1),  102, 15, IPPROTO_TCP}, 3},
	{{IPv4(235,1,2,8), IPv4(100,10,0,1),  101, 14, IPPROTO_TCP}, 4},
	{{IPv4(229,2,3,4), IPv4(200,50,0,1),  110, 13, IPPROTO_TCP}, 5},
	{{IPv4(227,1,1,2), IPv4(100,30,0,1),  120, 12, IPPROTO_TCP}, 6},
	{{IPv4(225,2,2,2), IPv4(101,40,0,1),  130, 12, IPPROTO_TCP}, 7},	
};
#define L3FWD_HASH_ENTRIES	16
typedef struct rte_hash lookup_struct_t;
static lookup_struct_t *ipv4_l3fwd_lookup_struct[1];
static uint8_t ipv4_l3fwd_out_if[L3FWD_HASH_ENTRIES] __rte_cache_aligned;
static struct lcore_para lcore_para[NUM_OF_LCORES]= { NULL }; 

#define IPV4_L3FWD_NUM_ROUTES \
	(sizeof(ipv4_l3fwd_route_array) / sizeof(ipv4_l3fwd_route_array[0]))
static void
print_ipv4_key(struct ipv4_5tuple key)
{
	printf("IP dst = %08x, IP src = %08x, port dst = %d, port src = %d, "
		"proto = %d\n", (unsigned)key.ip_dst, (unsigned)key.ip_src,
				key.port_dst, key.port_src, key.proto);
}
/*              %%%%%%%%%%%%%%%%%%%%%%%             */
void populate_hash_table_with_multicast_add( void )
{
	//uint32_t _source_address = IPv4(172,16,1,2);
	//uint32_t _group_address = IPv4(225,53,6,13);
	int ret, testAvailableLcores = 3, n = 1;
	struct ipv4_5tuple key_test;
	std::list<uint32_t>::iterator li;
	std::list<struct iState>::iterator iter;
	iter = InterfaceState.begin();
	while(iter != InterfaceState.end())
	{
		li = iter->source_list_include.begin();
		key_test.ip_dst = iter->groupAddress;
		//key_test.ip_src = iter->source_list_include.pop_front();
		key_test.ip_src = *li;
		key_test.port_dst         = 0;
		key_test.port_src         = 0;
		key_test.proto            = IPPROTO_UDP;
		if(iter->source_list_include.size() > 1)
		{
			rte_exit(EXIT_FAILURE, "hash table is not supported yet for multiple source lists\n");
		}	
		ret = rte_hash_add_key (ipv4_l3fwd_lookup_struct[0], (void *) &key_test);
		if (ret < 0) 
		{
			rte_exit(EXIT_FAILURE, "Unable to add entry to the"
						"l3fwd hash on socket\n");
		}
		// testAvailableLcores: starts from lcore 3
		ipv4_l3fwd_out_if[ret] = testAvailableLcores;
		// commented! because we dont have to change
		//NewAddresses[testAvailableLcores].sourceAdd = htonl(_source_address);
		//NewAddresses[testAvailableLcores].groupAdd = htonl(_group_address + IPv4(0,10*n,0,0));
		testAvailableLcores++;
		iter++;
		n++;
	}
	// {{IPv4(231,1,2,8), IPv4(200,80,0,1),  102, 15, IPPROTO_TCP}, 3},
}
static void
setup_hash(int socketid)
{
	struct rte_hash_parameters ipv4_l3fwd_hash_params;
	ipv4_l3fwd_hash_params.name = NULL,
	ipv4_l3fwd_hash_params.entries = L3FWD_HASH_ENTRIES,
	ipv4_l3fwd_hash_params.key_len = sizeof(struct ipv4_5tuple),
	ipv4_l3fwd_hash_params.hash_func = DEFAULT_HASH_FUNC,
	ipv4_l3fwd_hash_params.hash_func_init_val = 0;
	
	unsigned i;
	int ret;
	char s[64];

	/* create ipv4 hash */
	snprintf(s, sizeof(s), "ipv4_l3fwd_hash_%d", socketid);
	ipv4_l3fwd_hash_params.name = s;
	ipv4_l3fwd_hash_params.socket_id = socketid;
	ipv4_l3fwd_lookup_struct[socketid] =
		rte_hash_create(&ipv4_l3fwd_hash_params);
	printf("hash created \n");
	sleep(1);
	if (ipv4_l3fwd_lookup_struct[socketid] == NULL)
		rte_exit(EXIT_FAILURE, "Unable to create the l3fwd hash on "
				"socket %d\n", socketid);
	populate_hash_table_with_multicast_add();
	//print_ipv4_key(ipv4_l3fwd_route_array[i].key);
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
int setup_lcore_parameters(void)
{
	char worker_rx[][15] = {"worker_rx00", "worker_rx01", "worker_rx02", "worker_rx03", "worker_rx04", "worker_rx05", "worker_rx06", "worker_rx07"};
	char worker_tx[][15] = {"worker_tx00", "worker_tx01", "worker_tx02", "worker_tx03", "worker_tx04", "worker_tx05", "worker_tx06", "worker_tx07"};
	int x;
	for(x = 0; x < NUM_OF_LCORES; x++)
	{
		puts(&worker_rx[x][0]);
		lcore_para[x].worker_rx = rte_ring_create(&worker_rx[x][0], 128, 0, 
												 RING_F_SP_ENQ | RING_F_SC_DEQ);
		lcore_para[x].worker_tx = rte_ring_create(&worker_tx[x][0], 128, 0, 
												 RING_F_SP_ENQ | RING_F_SC_DEQ);
		if(lcore_para[x].worker_rx == NULL || lcore_para[x].worker_tx == NULL)
		{
			rte_exit(EXIT_FAILURE, "Unable to create ring %d\n", x);
		}
		lcore_para[x].missed_x = 0;
		lcore_para[x].missed_y = 0;
	}
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
bool buildKeyFromPacket(struct ipv4_5tuple *key_test, struct rte_mbuf *data_pkt)
{
	uint32_t destIp;
	uint16_t protocol = 0;
	protocol = getProtocol(data_pkt);
	if(protocol == 17)
	{
		// udp packet
		destIp = getDestinationIp(data_pkt);
		if(IS_IPV4_MCAST(destIp) == 0)
			return false;
		key_test->ip_dst   = destIp; 
		key_test->ip_src   = getSourceIp(data_pkt);
		key_test->port_dst = 0; //getDestinationPort(data_pkt);
		key_test->port_src = 0; //getSourcePort(data_pkt);
		key_test->proto    = getProtocol(data_pkt);
		return true;
	}
	else
		return false;
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
int insertVlanTag(struct rte_mbuf *mbuf)
{
	printf("vlan_insert %d\n", rte_vlan_insert(&mbuf));
	struct ether_hdr *eth_hdr;
	struct vlan_hdr *vlh;
	vlh = (struct vlan_hdr*)(rte_pktmbuf_mtod(mbuf, char*)+sizeof(struct ether_hdr));
	vlh->vlan_tci = htons(49172);
	return 0;
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
uint16_t calc_checksum(uint16_t *buf, int length)
{
    uint64_t sum;

    // checksum is calclated by 2 bytes
    for (sum=0; length>1; length-=2) 
        sum += *buf++;

    // for an extra byte
    if (length==1)
        sum += (char)*buf;

    // this can calc the 1's complement of the sum of each 1's complement
    sum = (sum >> 16) + (sum & 0xFFFF);  // add carry
    sum += (sum >> 16);          // add carry again
    return ~sum;
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
uint32_t parseIPV4string(char *ipAddress)
{
	printf("strlen = %d\n", strlen(ipAddress));
	puts(ipAddress);
	uint32_t ipbyte[4];
	//uint32_t ipbyte0 = 0, ipbyte1 = 0, ipbyte2 = 0, ipbyte3 = 0;
	//sscanf(ipAddress, "%uhh.%uhh.%uhh.%uhh", &ipbyte3, &ipbyte2, &ipbyte1, &ipbyte0);
	char arr[5] = {'\0','\0','\0','\0', '\0'};
	int x = 0, ind = 3, indarr = 0;
	int len;
	while(  x<strlen(ipAddress) )  
	{
		while(  ipAddress[x] != '.' )
		{
			arr[indarr]=ipAddress[x];
			x++;
			indarr++;
			if(ipAddress[x] == '\0')
				break;
			//printf("x = %d\n", x);
		}
		
		
		indarr++;
		arr[indarr] = '\0';
		ipbyte[ind--] = atoi(arr);
		//printf("atoi = %d\n", atoi(arr));
		indarr = 0;
		arr[0] = '\0';
		arr[1] = '\0';
		arr[2] = '\0';
		arr[3] = '\0';
		if((ipAddress[x]) == '\0')
			break;
		x++;
		
	}
	
	//printf("\nipbyte[0] = %d\n", ipbyte[0]);
	//printf("ipbyte[1] = %d\n", ipbyte[1]);
	//printf("ipbyte[2] = %d\n", ipbyte[2]);
	//printf("ipbyte[3] = %d\n", ipbyte[3]);
	
	uint32_t ipadd = ipbyte[0] | (ipbyte[1] << 8) | (ipbyte[2] << 16) | (ipbyte[3] << 24);
	return ipadd;
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
int sendPacketQ(struct rte_mbuf **mbuf, int port)
{
	int ret;
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	ret = rte_ring_sp_enqueue(lcore_para[lcore_id].worker_tx, (void *)mbuf[0]);
	return ret;
}
int sendPacket(struct rte_mbuf **mbuf, int port)
{
	int ret;
	//e_spinlock_lock(&spinlock_conf[port]);
	ret = rte_eth_tx_burst(port, 0, mbuf, 1);
	if(ret <= 0)
	{
		//notSent++;
		//printf("Packet Not sent\n");
	}
	else
	{
		//printf("Packet sent %d\n", ret);
	}
	//e_spinlock_unlock(&spinlock_conf[port]);
	//rte_pktmbuf_free(*mbuf);
	return ret;
}
static int parse_args(int argc, char **argv)
{
	char ip4Address[30], srcAddress[30];
	struct iState iStateObj1;
	int opt, id = 0, st = 0, en = 0, k, ret;
	char **argvopt;
	int option_index = 0, n;
	char *prgname = argv[0];
	static struct option lgopts[] = { {NULL, 0, 0, 0} };
	argvopt = argv;
	while(( opt = getopt_long(argc, argvopt, "m:q:s:", lgopts, &option_index))  != EOF)
	{
		switch(opt)
		{
			case 'm':
				strcpy(ip4Address, optarg);
				puts(ip4Address);
				multiCastIp = parseIPV4string(ip4Address);
				//printf("multiCastIp: %x, strlen = %d, argc = %d\n",multiCastIp, strlen(optarg), argc);
				for(n = 1; n < argc; n++)
				{
					if( strcmp(argv[n], "-m") == 0)
					{
						while( n < argc)
						{
							st = n+1;
							en = st;
							if( (st >= argc) || strlen(argv[st])==2 )
								break;
							for(k = st+1; k<argc; k++)
							{
								ret = IS_IPV4_MCAST(parseIPV4string(argv[k]));
								//printf("multicast IP: %d\n", ret);
								if(ret == 0 && strlen(argv[k])>6)
								{
									en = en + 1;
								}
								else
									break;
							}
							for(k = st; k<=en; k++)
							{
								//printf("k =  %d: ", k);
								//puts(argv[k]);
								//sleep(5);
								ret = IS_IPV4_MCAST(parseIPV4string(argv[k]));
								if(ret == 1)
								{
									iStateObj1.ID = id++;
									iStateObj1.groupAddress = parseIPV4string(argv[k]);
								}
								else
								{
									iStateObj1.source_list_include.push_back(parseIPV4string(argv[k]));
								}
							}
							InterfaceState.push_back(iStateObj1);
							iStateObj1.source_list_include.clear();
							//iStateObj1.groupAddress = 0;
							n = en;
							
							//printf("\t\tst %d, en %d, argc %d\n", st, en, argc);
							puts(argv[n]);
							sleep(1);
							
							//puts(argv[n]);
							
						}
					}
				}
				
			break;
			case 'q':
				printf("we are in option q\n");
			break;
			case 's':
				strcpy(srcAddress, optarg);
				igmpSourceIp = parseIPV4string(srcAddress);
				puts(srcAddress);
				sleep(1);
				break;
			default:
				printf("please enter valid options!!\n");	
		}
	}
	return 0;
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
static int
lcore_Distributer(void)
{
	unsigned lcore_id, lcoreID;
	bool timerSet = false;
	bool k;
	uint8_t type;
	int ret, numPackets;
	struct rte_mbuf *data_pkt[MAX_PKT_BURST];
	struct ipv4_5tuple key_test;
	lcore_id = rte_lcore_id();
	printf("hello from Distributer lcore %u\n", lcore_id);
	// ret = function_hash();
	setup_lcore_parameters();
	int missed = 0;
	while(!force_quit)
	{
		// port id, Queue id
		numPackets = rte_eth_rx_burst(0, 0, data_pkt, MAX_PKT_BURST);
		for(int x = 0; x < numPackets; x++)
		{
			rte_vlan_strip(data_pkt[x]);
			//assignNewIpSourceGroup(data_pkt[x], (int)lcore_id);
			//rte_eth_tx_burst(1, 0, &data_pkt[x], 1);
			//while(1);
			type = packetType(data_pkt[x]);     // 0 = rtp, 1 = fec, 2 = other
			printf("type = %d\n", type);
			k = buildKeyFromPacket(&key_test, data_pkt[x]);
			if(k == true)
			{
				/* first we lookup into hash table! if not found we add it into H table */
				ret = rte_hash_lookup(ipv4_l3fwd_lookup_struct[0], (const void *)&key_test);
				if(ret < 0)
				{
					
					int r = rte_ring_sp_enqueue(lcore_para[2].worker_rx, (void *)data_pkt[x]);
					if(r!=0)
					{
						//printf("missed =  %d \n", missed++);
						lcore_para[2].missed_x += 1;
					}
					
				}
				else if(ret >= 0)
				{
					/* key already in hash table! */
					lcoreID = ipv4_l3fwd_out_if[ret];
					printf("MC hash lcoreID %d\n", lcoreID);
					int n = rte_ring_sp_enqueue(lcore_para[lcoreID].worker_rx, (void *)data_pkt[x]); 
					if(n!=0)
					{
						//printf("missed =  %d, %u\n", missed++, lcoreID);
						lcore_para[lcoreID].missed_x += 1;
					}
				}
			}
			else
			{
				rte_pktmbuf_free(data_pkt[x]);
			}
		}
	}
	printStats();
	return ret;
}
/// %%%%%%%%%%-------End of Distributer Lcore functions--------%%%%%%%%%%%%%%%%%%%////
static int
lcore_IGMP(void)
{
	bool timerSet = false, exitFromLoop = true;
	int numPackets = 0;
	uint8_t type;
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	struct rte_mbuf *data_pkt[MAX_PKT_BURST];
	//sleep(4);
	printf("hello from lcore_IGMP %u\n", lcore_id);
	printf(" \n");
	void *pkts[64];
	
	while(!force_quit)
	{ 
		//printf("lcore_para[2].worker_rx == NULL :%d \n", lcore_para[2].worker_rx == NULL);
		//printf("rte_ring_empty(lcore_para[2].worker_rx) != 1 :%d \n", rte_ring_empty(lcore_para[2].worker_rx) != 1);
		if(lcore_para[2].worker_rx != NULL)
		{
			numPackets = rte_ring_dequeue_burst(lcore_para[2].worker_rx, pkts,32, NULL);
			if(numPackets)
			{
				//printf("numPackets = %d\n", numPackets);
				for(int k = 0; k<numPackets; k++)
				{
					data_pkt[k] = (struct rte_mbuf *)pkts[k];
					type = packetType(data_pkt[k]);
					if(type == IGMP)
						timerSet = igmpPacket(data_pkt[k]);
					else
						rte_pktmbuf_free(data_pkt[k]);
				}
					//numPackets = 0;
			}
		}
		else
		{
			//printf("Nothing in IGMP ring \n");
		}
	}
}
static void printStats()
{
	printf("============ Packet Lost Statistics ===============\n");
	for(int x = 0; x < NUM_OF_LCORES; x++)
	{
		printf("LCORE_ID [ %d ] : %d\n", x, lcore_para[x].missed_x);
	}
}
static int
lcore_TX(void)
{
	/* get all sorts of Tx packets and send them to ports */
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	printf("hello from lcore_TX %u\n", lcore_id);
	printf(" \n");
	int x;
	unsigned count = 0;
	unsigned int available = 0;
	void *pkts[64];
	while(!force_quit)
	{
		for(x = 0; x < NUM_OF_LCORES; x++)
		{
			if(lcore_para[x].worker_tx == NULL)
				continue;
			count = rte_ring_sc_dequeue_burst(lcore_para[x].worker_tx, (void **)pkts, 32, NULL);
			for(int n = 0; n < count; n++)
			{
				int sent = sendPacket((struct rte_mbuf **)&pkts[n], 1);
				//printf("sending lcore = %d, status = %d\n", x, sent);
			}
			//printf("lcore-Tx loop\n");
		}
	}
	
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
void constIgmpPacket(struct rte_mbuf *created_pkt, int queryType, uint32_t groupAddress)
{
	// test code for inserting source and GA into Membership reports //
	union {
		uint64_t as_int;
		struct ether_addr as_addr;
	} mc_eth_addr1;
	int nSources;
	groupAddress = groupAdd;
	//list <string> source_list_include
	std::list <uint32_t>::iterator li;
	std::list<struct iState>::iterator iter, iter2;
	iter = InterfaceState.begin();
	uint16_t numberOfGroupRecords = InterfaceState.size();
	nSources = iter->source_list_include.size();
	// calculating size of payload of igmp packet
	int tempPayload = 0;
	while(iter != InterfaceState.end())
	{
		if(queryType == GENERAL_QUERY)
		{
			// for each GroupAddress + Rec Type + Aux data Len + Numb of Sources fields
			tempPayload = tempPayload + 8; 
			// for each source list size belong to specific Group Record
			tempPayload = tempPayload + (iter->source_list_include.size())*4; 
			iter++;
			//printf("tempPaload size  = %d\n", tempPayload);
		}
		if(queryType == GROUP_QUERY)
		{
			if(groupAddress == iter->groupAddress)
			{
				// for each GroupAddress + Rec Type + Aux data Len + Numb of Sources fields
				tempPayload = tempPayload + 8; 
				// for each source list size belong to specific Group Record
				tempPayload = tempPayload + (iter->source_list_include.size())*4; 
				iter++;
				numberOfGroupRecords = 1;
				break;  // because only one such record should exist for particular group
			}
		}
	}
	uint8_t *payload1, *payload2;
	struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
	struct igmpv3_hdr *igmpv3;
	struct groupRecord *gRec;
	uint32_t *nS;
	uint32_t bond_ip = BOND_IP_1 | (BOND_IP_2 << 8) | (BOND_IP_3 << 16) | (BOND_IP_4 << 24);
	size_t pkt_size;
	pkt_size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct igmpv3_hdr)
																  + tempPayload;
																  //+ sizeof(struct groupRecord)
	    														  //+ sizeof(uint32_t)*nSources; 
	//TODO: only for 1 source and 1 group record. 
	//printf("pkt_size %d\n", pkt_size);
	created_pkt->data_len = pkt_size;
    created_pkt->pkt_len = pkt_size;
	eth_hdr = rte_pktmbuf_mtod(created_pkt, struct ether_hdr *);
	eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	rte_eth_macaddr_get(0, &ports_eth_addr[0]);
	ether_addr_copy(&ports_eth_addr[0], &eth_hdr->s_addr);
	//print_ethaddr(" [i]dst Address: ", &eth_hdr->d_addr);	
	ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(created_pkt, char *) + sizeof(struct ether_hdr));
	ip_hdr->version_ihl = 0x45;
	ip_hdr->type_of_service = 0xc0;
	ip_hdr->total_length = htons(pkt_size-sizeof(struct ether_hdr));  
	ip_hdr->packet_id = 1;
	ip_hdr->fragment_offset = htons(0x4000);
	ip_hdr->time_to_live = 1;
	ip_hdr->next_proto_id = 2;
	ip_hdr->hdr_checksum  =  0;
	ip_hdr->src_addr = htonl(igmpSourceIp);             
	if(queryType == GENERAL_QUERY || queryType == GROUP_SOURCE_QUERY)
	{
		ip_hdr->dst_addr = htonl(parseIPV4string("224.0.0.22"));
		mc_eth_addr1.as_int = ETHER_ADDR_FOR_IPV4_MCAST((parseIPV4string("224.0.0.22")));
	}
	else if(queryType == GROUP_QUERY)
	{
		ip_hdr->dst_addr = htonl(groupAddress);
		mc_eth_addr1.as_int = ETHER_ADDR_FOR_IPV4_MCAST(groupAddress);
	}
	ether_addr_copy(&mc_eth_addr1.as_addr, &eth_hdr->d_addr);
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
	
	
	igmpv3 = (struct igmpv3_hdr *)(rte_pktmbuf_mtod(created_pkt, char *) 
							            + sizeof(struct ether_hdr) 
							            + sizeof(struct ipv4_hdr));
	payload1 = (uint8_t *)(rte_pktmbuf_mtod(created_pkt, char *) 
							            + sizeof(struct ether_hdr) 
							            + sizeof(struct ipv4_hdr)) 
										+ sizeof(struct igmpv3_hdr);
	payload2 = (uint8_t *)(rte_pktmbuf_mtod(created_pkt, char *) 
							            + sizeof(struct ether_hdr) 
							            + sizeof(struct ipv4_hdr)) 
										+ sizeof(struct igmpv3_hdr)
										+ sizeof(struct groupRecord);
	igmpv3->type = 0x22;
	igmpv3->reserved1 = htons(0);
	igmpv3->checksum = htons(0);
	igmpv3->reserved2 = htons(0);
	igmpv3->nGroupRecords = htons(numberOfGroupRecords);    
	uint32_t *sources;
	//printf("tempPayload: %d, groupAddress: %x, NR: %d\n", tempPayload, groupAddress, htons(igmpv3->nGroupRecords));
	// gothrough all ports or interfaces
	iter = InterfaceState.begin();
	while(iter != InterfaceState.end())
	{
		if(queryType == GROUP_QUERY)
		{
			
			if(groupAddress != iter->groupAddress)
			{
				iter++;
				continue;
			}
			// In case of unmatched groupAdd we should skip that (all) records
		}
		gRec = (struct groupRecord*)payload1;
		if(iter->source_list_include.size() == 0)
			gRec->rtype = 2; // MODE_IS_EXCLUDE;
		else
			gRec->rtype = 1; // MODE_IS_INCLUDE;
		gRec->auxDataLen = 0;
		gRec->nSources = htons(iter->source_list_include.size());
		gRec->multiCastAdd = htonl(iter->groupAddress);
		//printf("XXXXXXXXXXX groupAddress  = %x , tempPayload %d\n", htonl(iter->groupAddress), tempPayload);
		payload1 = (uint8_t*)payload1 + sizeof(struct groupRecord);
		sources = (uint32_t*)payload1;
		li = iter->source_list_include.begin();
		while(li != iter->source_list_include.end()) 
		{
			*sources = htonl(*li);
			sources = sources + 1;
			//printf("%x \n", htonl(*li));
			li++;
		}
		//printf("nSources = %d\n", nSources);
		iter++;
		payload1 = (uint8_t*)sources;
		
	}
	igmpv3->checksum = calc_checksum((uint16_t*)igmpv3, sizeof(struct igmpv3_hdr) + tempPayload);
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
/* timer0 callback */
static void
IgmpV3GeneralQueryReport(__attribute__((unused)) struct rte_timer *tim,
	  							__attribute__((unused)) void *arg)
{
	//printf("into fun\n");
	int nSources;
	uint32_t groupAdd;
	unsigned lcore_id = rte_lcore_id();
	//printf("%s() on lcore %u\n", __func__, lcore_id);
	struct rte_mbuf *mbuf;
	if(packetMbufsSource(&mbuf, 1))
	{
		constIgmpPacket(mbuf, GENERAL_QUERY, 0);
		int ret = insertVlanTag(mbuf);
		if(rte_eth_tx_burst(0, 0, &mbuf, 1))
			printf("REPORT SENT\n");
		else
			printf("REPORT NOT SENT\n");
	}
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
/* Group specific timer callback */
static void
IgmpV3GroupQueryReport(__attribute__((unused)) struct rte_timer *tim,
	  							__attribute__((unused)) void *arg)
{
	//uint32_t groupAdd = *((uint32_t *)arg);
	//printf("xxinto fun %x\n", groupAdd);
	int nSources;
	unsigned lcore_id = rte_lcore_id();
	//printf("%s() on lcore %u\n", __func__, lcore_id);
	struct rte_mbuf *mbuf;
	if(packetMbufsSource(&mbuf, 1))
	{
		constIgmpPacket(mbuf, GROUP_QUERY, 0);
		int ret = insertVlanTag(mbuf);
		if(rte_eth_tx_burst(0, 0, &mbuf, 1))
			printf("REPORT SENT\n");
		else
			printf("REPORT NOT SENT\n");
	}
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
/*   igmp control functions  */
uint8_t getResponseCode(struct rte_mbuf * igmpPkt, int igmpVersion)
{
	struct ipv4_hdr *iph;
	iph = (struct ipv4_hdr *)(rte_pktmbuf_mtod(igmpPkt, char *) + sizeof(struct ether_hdr));
	uint16_t ip_hdr_length = (iph->version_ihl & 0x0f)*4;
	if( (igmpVersion == GENERAL_QUERY_V2) || ( igmpVersion == GROUP_QUERY_V2) )
	{
		struct igmpv2Query *igmpv2query;	
		igmpv2query = (struct igmpv2Query *)(rte_pktmbuf_mtod(igmpPkt, char *) 
											+ sizeof(struct ether_hdr) 
											+ ip_hdr_length);
		return(igmpv2query->responseCode); 
	}
	else
	{
		struct igmpv3Query *igmpv3Query;	
		igmpv3Query = (struct igmpv3Query *)(rte_pktmbuf_mtod(igmpPkt, char *) 
											+ sizeof(struct ether_hdr) 
											+ ip_hdr_length);
		return(igmpv3Query->responseCode);
	}
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
int queryType(struct rte_mbuf * igmpPkt)
{
	struct ether_hdr *eth_hdr;
	struct ipv4_hdr *iph;
	iph = (struct ipv4_hdr *)(rte_pktmbuf_mtod(igmpPkt, char *) + sizeof(struct ether_hdr));
	uint16_t length = htons(iph->total_length) - (iph->version_ihl & 0x0f)*4;
	uint16_t ip_hdr_length = (iph->version_ihl & 0x0f)*4;
	//printf("htons(iph->total_length) = %d\n", htons(iph->total_length));
	//printf("(iph->version_ihl & 0x0f)*4 = %d\n", (iph->version_ihl & 0x0f)*4);
	if(length == 8)
	{
		struct igmpv2Query *igmpv2query;	
		igmpv2query = (struct igmpv2Query *)(rte_pktmbuf_mtod(igmpPkt, char *) 
											+ sizeof(struct ether_hdr) 
											+ ip_hdr_length);
		if(igmpv2query->type == 0x16)
		{
			rte_pktmbuf_free(igmpPkt);
			return 5;
		}
		else if(htonl(igmpv2query->groupAdd) == 0)
			return 3; // general Query igmpv2
		else 
		{
			//printf("group add %x, sizeof(struct ipv4_hdr) = %d\n", htonl(igmpv2query->groupAdd), sizeof(struct ipv4_hdr));
			return 4; // group specific igmpv2 Query
		}
	}
	struct igmpv3Query *igmpv3Query;	
	igmpv3Query = (struct igmpv3Query *)(rte_pktmbuf_mtod(igmpPkt, char *) 
							            + sizeof(struct ether_hdr) 
							            + ip_hdr_length);
	if(igmpv3Query->type == 0x22)
	{
			rte_pktmbuf_free(igmpPkt);
			return 5;
	}
	else if(htonl(igmpv3Query->groupAdd) == 0)
		return 0; // general Query
	else if( (htonl(igmpv3Query->groupAdd) != 0) && (htons(igmpv3Query->nSources) == 0) )
		return 1; // group specific Query
	else if( (htonl(igmpv3Query->groupAdd) != 0) && (htons(igmpv3Query->nSources) != 0) )
		return 2; // group and source specific Query
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
uint32_t getGroupAddress(struct rte_mbuf * igmpPkt)
{
	struct ipv4_hdr *iph;
	iph = (struct ipv4_hdr *)(rte_pktmbuf_mtod(igmpPkt, char *) + sizeof(struct ether_hdr));
	uint16_t ip_hdr_length = (iph->version_ihl & 0x0f)*4;
	struct igmpv3Query *igmpv3Query;	
	igmpv3Query = (struct igmpv3Query *)(rte_pktmbuf_mtod(igmpPkt, char *) 
							            + sizeof(struct ether_hdr) 
							            + ip_hdr_length);
	return(htonl(igmpv3Query->groupAdd));
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
uint32_t getSourceAddress(struct rte_mbuf * igmpPkt)
{
	struct ipv4_hdr *iph;
	iph = (struct ipv4_hdr *)(rte_pktmbuf_mtod(igmpPkt, char *) + sizeof(struct ether_hdr));
	uint16_t ip_hdr_length = (iph->version_ihl & 0x0f)*4;
	struct igmpv3Query *igmpv3Query;
	uint8_t *temp;
	temp = (uint8_t *)(rte_pktmbuf_mtod(igmpPkt, char *) 
							            + sizeof(struct ether_hdr) 
							            + ip_hdr_length
										+ sizeof(struct igmpv3Query));	
	return(htonl(*((uint32_t *)temp)));
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
uint32_t findGroupRecord(struct rte_mbuf * igmpPkt)
{
	uint32_t groupAdd1 = getGroupAddress(igmpPkt);
	//printf("GroupAdd = %x", (groupAdd));
	std::list <uint32_t>::iterator li;
	std::list<struct iState>::iterator iter;
	iter = InterfaceState.begin();
	while(iter != InterfaceState.end())
	{
		if(iter->groupAddress == groupAdd1) 
			return (iter->groupAddress);
		iter++;
	}
	return 0;
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
uint32_t findGroupAndSourceRecord(struct rte_mbuf * igmpPkt)
{
	uint32_t groupAdd1 = getGroupAddress(igmpPkt);
	//printf("GroupAdd :findG= %x", (groupAdd1));
	std::list <uint32_t>::iterator li;
	std::list<struct iState>::iterator iter;
	iter = InterfaceState.begin();
	while(iter != InterfaceState.end())
	{
		if(iter->groupAddress == groupAdd1) 
		{
			li = iter->source_list_include.begin();
			while(li != iter->source_list_include.end()) 
			{
				if( getSourceAddress(igmpPkt) == *li )
					return(iter->groupAddress); 
				//printf("%x \n", htonl(*li));
				li++;
			}
		}
		iter++;
	}
	return 0;
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
int constIgmpv2Packet(struct rte_mbuf *created_pkt, int queryType, uint32_t groupAddress)
{
	union {
		uint64_t as_int;
		struct ether_addr as_addr;
	} mc_eth_addr1;
	struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
	struct igmpv2Query *igmpv2query;
	size_t pkt_size;
	pkt_size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct igmpv2Query);  
	//printf("pkt_size %d\n", pkt_size);
	created_pkt->data_len = pkt_size;
    created_pkt->pkt_len = pkt_size;
	eth_hdr = rte_pktmbuf_mtod(created_pkt, struct ether_hdr *);
	eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	rte_eth_macaddr_get(0, &ports_eth_addr[0]);
	ether_addr_copy(&ports_eth_addr[0], &eth_hdr->s_addr);
	//print_ethaddr(" [i]dst Address: ", &eth_hdr->d_addr);	
	ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(created_pkt, char *) + sizeof(struct ether_hdr));
	ip_hdr->version_ihl = 0x45;
	ip_hdr->type_of_service = 0xc0;
	ip_hdr->total_length = htons(pkt_size-sizeof(struct ether_hdr));  
	ip_hdr->packet_id = 1;
	ip_hdr->fragment_offset = htons(0x4000);
	ip_hdr->time_to_live = 1;
	ip_hdr->next_proto_id = 2;
	ip_hdr->hdr_checksum  =  0;
	ip_hdr->src_addr = htonl(igmpSourceIp);             
	ip_hdr->dst_addr = htonl(groupAddress);
	mc_eth_addr1.as_int = ETHER_ADDR_FOR_IPV4_MCAST(groupAddress);
	ether_addr_copy(&mc_eth_addr1.as_addr, &eth_hdr->d_addr);
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);
	igmpv2query = (struct igmpv2Query *)(rte_pktmbuf_mtod(created_pkt, char *) 
							            + sizeof(struct ether_hdr) 
							            + sizeof(struct ipv4_hdr));
	igmpv2query->type = 0x16;          // v2 membership report
	igmpv2query->responseCode = 0;
	igmpv2query->checksum = htons(0);
	igmpv2query->groupAdd = htonl(groupAddress);  // TODO
	igmpv2query->checksum = calc_checksum((uint16_t*)igmpv2query, sizeof(struct igmpv2Query));
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
/* V2 General Query Response timer callback */
static void
IgmpV2GeneralQueryReport(__attribute__((unused)) struct rte_timer *tim,
	  							__attribute__((unused)) void *arg)
{
	int *id = (int *)arg;
	std::list<struct iState>::iterator iter;
	iter = InterfaceState.begin();
	while(iter != InterfaceState.end())
	{
		if(iter->ID == *id)
		{
			break;
		}
		iter++;
	} 
	struct rte_mbuf *mbuf;
	if(packetMbufsSource(&mbuf, 1))
	{
		constIgmpv2Packet(mbuf, GENERAL_QUERY_V2, iter->groupAddress);
		int ret = insertVlanTag(mbuf);
		if(rte_eth_tx_burst(0, 0, &mbuf, 1))
			printf("REPORT SENT %x\n", iter->groupAddress);
		else
			printf("REPORT NOT SENT\n");
	}

}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
/* V2 General Specefic timer callback */
static void
IgmpV2GroupSpeceficReport(__attribute__((unused)) struct rte_timer *tim,
	  							__attribute__((unused)) void *arg)
{
	std::list<struct iState>::iterator iter;
	iter = InterfaceState.begin();
	while(iter != InterfaceState.end())
	{
		if(iter->groupAddress == groupAdd)
		{
			break;
		}
		iter++;
	} 
	struct rte_mbuf *mbuf;
	if(packetMbufsSource(&mbuf, 1))
	{
		constIgmpv2Packet(mbuf, GROUP_QUERY_V2, iter->groupAddress);
		int ret = insertVlanTag(mbuf);
		if(rte_eth_tx_burst(0, 0, &mbuf, 1))
			printf("REPORT SENT %x\n", iter->groupAddress);
		else
			printf("REPORT NOT SENT\n");
	}

}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
bool igmpPacket(struct rte_mbuf * igmpPkt)
{
	uint8_t maxResTimeX;
	int type = queryType(igmpPkt);
	if(type == 5)
		return false;
	maxResTimeX = getResponseCode(igmpPkt, type);
	float maxResTime = (float)(rand()%maxResTimeX)/10;
	//printf("type_QUERY %d,   maxResTime = %f, maxResTimeX = %d\n", type, maxResTime, maxResTimeX);
	//while(1);
	uint64_t hz;
	unsigned lcore_id;
	rte_timer_subsystem_init();
	hz = rte_get_timer_hz();
	lcore_id = rte_lcore_id();
	int n = 0;
	if(type == GENERAL_QUERY_V2)   
	{
		std::list<struct iState>::iterator iter;
		iter = InterfaceState.begin();
		while(iter != InterfaceState.end())
		{
			iter->ID = n;   // if it was not set already, used to id particular record
			rte_timer_init(&gen[n]);
			maxResTime = (float)(rand()%maxResTimeX)/10;
			rte_timer_reset(&gen[n++], maxResTime*hz, SINGLE, lcore_id, IgmpV2GeneralQueryReport, (void *)&iter->ID);
			iter->ID = iter->ID + 1;
		iter++;
		}
	
	}
	else if (type == GROUP_QUERY_V2)
	{
		//TODO IgmpV2GroupSpeceficReport
		groupAdd = findGroupRecord(igmpPkt);
		if( groupAdd != 0)
			rte_timer_reset(&gen[0], maxResTime*hz, SINGLE, lcore_id, IgmpV2GroupSpeceficReport, NULL);
			
	}
	else if(type == GENERAL_QUERY)
	{
		//printf("GENERAL_QUERY\n");
		static struct rte_timer timer_gen;
		rte_timer_init(&timer_gen);
		//printf("--maxResTime*hz = %llu, hz = %llu\n", maxResTime*hz, hz);
		//while(1);
		rte_timer_reset(&timer_gen, maxResTime*hz, SINGLE, lcore_id, IgmpV3GeneralQueryReport, NULL);
		// PERIODICAL, SINGLE
	}
	else if(type == GROUP_QUERY)
	{
		static struct rte_timer timer_group;
		rte_timer_init(&timer_group);
		groupAdd = findGroupRecord(igmpPkt);
		//printf("--GroupAdd = %x\n", (groupAdd));
		if(groupAdd != 0)
		{
			rte_timer_reset(&timer_group, maxResTime*hz, SINGLE, lcore_id, IgmpV3GroupQueryReport, NULL);
		}
		else
			return false;
	}
	else if(type == GROUP_SOURCE_QUERY)
	{
		// groupAdd is global
		static struct rte_timer timer_group;
		rte_timer_init(&timer_group);
		groupAdd = findGroupAndSourceRecord(igmpPkt);
		//printf("xGROUP_SOURCE_QUERY %x\n", groupAdd);
		if(groupAdd != 0)
		{
			rte_timer_reset(&timer_group, maxResTime*hz, SINGLE, lcore_id, IgmpV3GroupQueryReport, NULL);
		}
		else
			return false;
	}
	else
	{
		rte_pktmbuf_free(igmpPkt);
		return false;
	}
	rte_pktmbuf_free(igmpPkt);
	return true;
}
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
/// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%---------------%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%////
void constRtpPacket(struct rte_mbuf *created_pkt, uint32_t multiCastIp, uint16_t sequenceNumber, uint32_t time_smp)
{
	unsigned lcore_id = rte_lcore_id();
	uint8_t *payload;
	uint32_t bond_ip = BOND_IP_1 | (BOND_IP_2 << 8) |
                          (BOND_IP_3 << 16) | (BOND_IP_4 << 24);
	uint32_t bond_ip1 = BOND_IP1_1 | (BOND_IP1_2 << 8) |
                          (BOND_IP1_3 << 16) | (BOND_IP1_4 << 24);
	struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp;
	struct rtp_hdr *rtp;
	size_t pkt_size;
	pkt_size = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr)
																  + sizeof(struct rtp_hdr)
																  + 1320; // recovered paylaod
	//+ 12 FEC Header removed
																   
	//printf("pkt_size %d\n", pkt_size);
    	created_pkt->data_len = pkt_size;
    	created_pkt->pkt_len = pkt_size;
	eth_hdr = rte_pktmbuf_mtod(created_pkt, struct ether_hdr *);
	eth_hdr->ether_type = rte_cpu_to_be_16(ETHER_TYPE_IPv4);
	//ether_addr_copy(&ports_eth_addr[0], &eth_hdr->s_addr);
	ether_addr_copy(&NewAddresses[lcore_id].mc_eth_addr[0], &eth_hdr->d_addr);  // (from _source, to _destination)
	ether_addr_copy(&NewAddresses[lcore_id].mc_eth_addr[1], &eth_hdr->s_addr); // (from _source, to _destination)
	// 08:00:27:d5:8b:6c
	/*
	eth_hdr->d_addr.addr_bytes[0] = 0x00;
	eth_hdr->d_addr.addr_bytes[1] = 0x1b;
	eth_hdr->d_addr.addr_bytes[2] = 0x21;
	eth_hdr->d_addr.addr_bytes[3] = 0x58;
	eth_hdr->d_addr.addr_bytes[4] = 0x34;
	eth_hdr->d_addr.addr_bytes[5] = 0x1c;
	*/
	//print_ethaddr(" dst Address:", &ports_eth_addr[0]);	
	ip_hdr = (struct ipv4_hdr *)(rte_pktmbuf_mtod(created_pkt, char *) + sizeof(struct ether_hdr));
	ip_hdr->version_ihl = 0x45;
	ip_hdr->type_of_service = 0xc0;
	ip_hdr->total_length = htons(pkt_size-sizeof(struct ether_hdr));    // doubt
	ip_hdr->packet_id = 1;
	ip_hdr->fragment_offset = htons(0x4000);
	ip_hdr->time_to_live = 19;
	ip_hdr->next_proto_id = 17;
	ip_hdr->hdr_checksum  =  0;
	ip_hdr->src_addr = htonl(NewAddresses[lcore_id].sourceIp);             //bond_ip
	ip_hdr->dst_addr = htonl(multiCastIp);  //multiCastIp //bond_ip1+1  //htonl(bond_ip+6);
	ip_hdr->hdr_checksum = rte_ipv4_cksum(ip_hdr);	
	udp = (struct udp_hdr *)(rte_pktmbuf_mtod(created_pkt, char *) 
							            + sizeof(struct ether_hdr) 
							            + sizeof(struct ipv4_hdr));
	udp->src_port    =  htons(NewAddresses[lcore_id].udpSrcPort);
    udp->dst_port    =  htons(NewAddresses[lcore_id].udpDestPort);
    udp->dgram_len   =  htons(sizeof(struct udp_hdr) + sizeof(struct rtp_hdr) + 1320 ); // + 12 is removed!
    udp->dgram_cksum =  0;
	rtp = (struct rtp_hdr *)(rte_pktmbuf_mtod(created_pkt, char *) 
							            + sizeof(struct ether_hdr) 
							            + sizeof(struct ipv4_hdr)
							            + sizeof(struct udp_hdr));
	
	rtp->synSource =  htonl(NewAddresses[lcore_id].synSource);
	//rtp->conSource =  htonl(0x12345678);
	rtp->seqNumber =  htons(sequenceNumber); // snn is removed
	rtp->timeStamp =  htonl(time_smp);       // TS  is removed
	rtp->payloadT = 33; 
	rtp->ver = 2;
	rtp->cc = 0;
	rtp->marker = 0;
	TS+=32;
	//udp->dgram_cksum =  rte_ipv4_cksum(ip_hdr);

}

// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
// %%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%



// Demonstration of how to use the C interface.
// This is kinda basic, we use only one function
// to encode, drop some (random) packets, and then
// decode what remains.

// Encode / decode "mysize" uint32_t
// for a more elaborate examlpe with different alignments, see test_cpp
void symbolWriteToPacket(struct rte_mbuf *pkt,  uint8_t *copyFrom, uint32_t dataLength);
bool decode (uint32_t mysize, float drop_prob, uint8_t overhead, struct rte_mbuf **pkt_arr);
void symbolWriteToPacket(struct rte_mbuf *pkt,  uint8_t *copyFrom, uint32_t dataLength)
{
	//printf("function: symbolWriteToPacket\n");
	uint8_t *payload;
	payload = (uint8_t *)(rte_pktmbuf_mtod(pkt, char *) 
							            + sizeof(struct ether_hdr) 
							            + sizeof(struct ipv4_hdr)
								        + sizeof(struct udp_hdr)
						  				+ sizeof(struct rtp_hdr));
	if( memcpy(payload, copyFrom, dataLength) == NULL )
	{
		printf("Fail To memcpy: recoverd symbol copy into Packet\n ");
	}
	//int ret = rte_eth_tx_burst(1, 0, &pkt, 1);
}
uint8_t packetType( struct rte_mbuf *pkt )
{
	struct ether_hdr *eth_hdr;
	struct rtp_hdr *rtp;
	struct ipv4_hdr *iph;
	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	if(rte_cpu_to_be_16(eth_hdr->ether_type) != ETHER_TYPE_IPv4)
		return 2;
	rtp = (struct rtp_hdr *)(rte_pktmbuf_mtod(pkt, char *) 
							            + sizeof(struct ether_hdr) 
							            + sizeof(struct ipv4_hdr)
								        + sizeof(struct udp_hdr));
	iph = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, char *) + sizeof(struct ether_hdr));
	//printf("check iph->next_proto_id = %d\n", iph->next_proto_id);
	if(iph->next_proto_id == 2)
		return IGMP;  // igmp packet 								  
	if(rtp->payloadT == 96)
	{
		return 1;     // fec packet
	}
	else if(rtp->ver == 2)
		return 0;     // rtp packet
	else 						  
		return 2;     // other...

}
uint16_t getSequenceNumber(struct rte_mbuf *pkt, bool mode)
{
	struct rte_mbuf *created_pkt;
	struct ether_hdr *eth_hdr;
    struct ipv4_hdr *ip_hdr;
	struct udp_hdr *udp;
	struct rtp_hdr *rtp;
	struct fec_hdr *fec;
	created_pkt = pkt;
	if(mode == 0)
	{
		rtp = (struct rtp_hdr *)(rte_pktmbuf_mtod(created_pkt, char *) 
											+ sizeof(struct ether_hdr) 
											+ sizeof(struct ipv4_hdr)
											+ sizeof(struct udp_hdr));
		//printf("seqNumber: %d\n ",rte_cpu_to_be_16(rtp->seqNumber));
		return(rte_cpu_to_be_16(rtp->seqNumber));
	}
	else
	{
		fec = (struct fec_hdr *)(rte_pktmbuf_mtod(created_pkt, char *) 
							            + sizeof(struct ether_hdr) 
							            + sizeof(struct ipv4_hdr)
										+ sizeof(struct udp_hdr)
										+ sizeof(struct rtp_hdr));
		return(rte_cpu_to_be_16(fec->sequenceNumberBase));
	}

}
void bufferDisplay(uint8_t *recoveryBuffer, int no)
{
		uint8_t *temp;
		temp = recoveryBuffer;
		if(no==1)
		{
			printf("\n ----------------->------------------\n");
			//printf("%x ", 0);
			for(int x = 0; x<1320; x++ )
			{
				printf("%x ", temp[x]);
				if(x%16 == 0)
				{
					//printf("%x ", x/16);
					printf("\n");
				}
			}
			printf("\n ----------------<-------------------\n");
		return;
		}
		int b;
		printf("\n -----------------------------------\n");
		for(int x = 0; x<20; x++ )
		{
			printf("%x ", temp[x]);
		}
		printf("\n");
		b = 1320;
		for(int x = 0; x<20; x++ )
		{
			printf("%x ", temp[b++]);
		}
		printf("\n");
		b = 2*1320;
		for(int x = 0; x<20; x++ )
		{
			printf("%x ", temp[b++]);
		}
		printf("\n");
		b = 3*1320;
		for(int x = 0; x<20; x++ )
		{
			printf("%x ", temp[b++]);
		}
		printf("\n -----------------------------------\n");
		printf("\n");
}

struct rte_mbuf*	recoverPacket( uint8_t *recoveryBuffer,
					int syncPacket, 
					int element,
					uint8_t *packetBuffer,
					uint8_t *fecBuffer, 
				    struct RaptorQ_ptr *dec_dummy)
{
	//////////////////////   decoder initialization    ////////////////////////
	//uint32_t oti_scheme = 16777476;
	//uint64_t oti_common;
	//oti_common	= 88583701800;
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	struct RaptorQ_ptr *dec;
	dec = RaptorQ_Dec (DEC_32, oti_common, oti_scheme);
	if (dec == NULL)
	{
		rte_exit(EXIT_FAILURE, "dec: decoder could not initiliazed \n");
	}
	RaptorQ_precompute(dec, 2, true);
	//////////////////////   decoder initialized    ////////////////////////
	int index = 0, dataIndex = 0, tempSyncPacket, fecPlace = 0;
	tempSyncPacket = syncPacket;
	
	//printf("run count of loop ");
	int id_array_ind = 0, id_array[20] = {-1};
	int mutilple = 0;
	for(int count = 0; count < D; count++)
	{
		// placing every thing (col) in buffer and recover missing packet
		if(syncPacket == element)
		{
			
			syncPacket = (syncPacket + L)%65536; // new
			mutilple = count;
			continue;
		}
		id_array[id_array_ind++] = count;
		//printf("syncPacket:%d ->loopVar: %d\n ",syncPacket, count);
		dataIndex = syncPacket * 2048;
		rte_memcpy ( (uint8_t*) &recoveryBuffer[ index ], &packetBuffer[dataIndex], 330*4);
		syncPacket = (syncPacket + L)%65536;
		
		index = index + (4*330);
		
	}
	id_array[id_array_ind++] = D;
	id_array_ind = 0;
	printf("\n");
	dataIndex = (tempSyncPacket%1000) * 2048;
	rte_memcpy ( (uint8_t*) &recoveryBuffer[ index ], &fecBuffer[dataIndex], 330*4);
	//printf("----Contents of RecoveryBuffer-----\n");
	//bufferDisplay(recoveryBuffer, 0);
	//printf("----==========================-----\n");
	// start decoding ...
	index = 0;
	
	for(int count = 0; count < D; count++)
	{
		uint32_t data_size = RaptorQ_symbol_size (dec) / sizeof(uint32_t);
		uint8_t *datax = &recoveryBuffer[index];
		uint32_t *data = (uint32_t *)datax;
		RaptorQ_add_symbol_id (dec, (void **)&data, data_size, id_array[id_array_ind]);  //count
		index = index + (330*4); // 4*330  $
		//printf("symbol_size %d, count(ID): %d\n", RaptorQ_symbol_size (dec), id_array[id_array_ind]);
		id_array_ind++;
	}
	
	uint32_t decoded_size = 0;
	decoded_size =  (size_t) RaptorQ_bytes(dec) / sizeof(uint32_t);
	//printf("--|--> decoded_size: %d,  RaptorQ_bytes (dec): %d \n", decoded_size, RaptorQ_bytes (dec));
	uint32_t *received = (uint32_t *) malloc (decoded_size * sizeof(uint32_t));  // should be "decoded_size" insted of 32 
	uint32_t *rec = received;
	uint64_t written = 0;	
	int twoTime = 4;
	while(!written)
		written = RaptorQ_decode (dec, (void **)&rec, decoded_size);  // same here
	uint64_t down3, down2, down1 = 0x00;
	down2 = down1;
	down3 = down1;
	while(down2-- > 0) { while(down1-- > 0){ while(down3-- > 0) { } } }
	//printf("written %llu\n", written);
	int end, start;
	start = 0+(mutilple*1320);
	end = 0+(mutilple*1320)+1320-1;
	int tenBytes = 1310;
	uint32_t time_smp;
	struct rte_mbuf *pkt[2];
	if(written)
	{
		uint8_t* dx = (uint8_t*)received;
		//printf("\n=============written=============\n");
		
		
		if(packetMbufsSource(pkt, 1))
		{
			constRtpPacket(pkt[0], NewAddresses[lcore_id].multiCastIp, element, time_smp);	
			symbolWriteToPacket(pkt[0], &dx[start], 1316);		
		}
		/*
		for(int j=(start); j<(end-tenBytes); j++)
		{
			if(j%16 == 0)
				printf("\n");
			printf("%x ", dx[j]);
			
		}
		*/
		//printf("\n=============--------=============\n");
		printf("\n");
	}
	free(received);
	RaptorQ_free (&dec);
	//printf("in recover function: testSeq#%d, element %d\n",getSequenceNumber(pkt[0], false), element);
	return (pkt[0]);
}
////////////////////////////////////////////////////////////////////
int checkMissingSourceSymbols(		int *LinearArray, 
							        int length,
									int *NotRecoverable,
									int *nlength,
									int *recover,
									int *syncPacketArray,
									int *rec_length,
							  		struct MarkDataSymbols *dataSymbols,
							  		struct blockIndex *sourceBlock
							 )
{
	//printf("checkMissingSourceSymbols %d\n", length);
	int n, missing = 0, temp = 0, x=0, syncPacket = 0, k, m, firstSourceSymMissing=0;
	//////////////////////////////////////////////////
	int diff = 0, index = -1, counter = 0, count=0;
	
	if(length < (L-1))
	{
		//printf("length of fec array %d\n", length);
		sourceBlock->startIndex = 0;
		sourceBlock->endIndex   = (LinearArray[length-1] + (L*(D-1)))%65536;
		return 0;
	}
	for(n = 0; n < (length-1); n++ )
	{
		diff = LinearArray[n+1]- LinearArray[n];
		//printf("CMSS diff = %d\n", diff);
		if(diff == 2 || diff == -65534)
		{
			index = n+1;
			break;
		}
		counter++;
	}
	*rec_length = 0;
	for(n = 0; n < length; n++)
	{
		syncPacket = LinearArray[n];  // Array containing Fec Seq Num 
		temp = LinearArray[n];
		missing = 0;
		for(m = 0; m < D; m++)
		{
			if(dataSymbols[temp].Mark == false)
			{
				missing++;
				firstSourceSymMissing = temp;
				//printf("lost pkt: %d\n", temp);
			}
			temp = (temp + L)%65536;
			//printf("temp = %d, temp%65535 = %d\n ", temp, temp%65535);
		}
		if(missing == 1)
		{
			recover[x] = firstSourceSymMissing;       // source packet to be recoverd
			syncPacketArray[x] = syncPacket;	// FEC packet used to recover missing symbol in column
			//printf("FUN: [Fec pkt: %d] [recover pkt: %d]\n", syncPacket, recover[x]);
			x++;
			*rec_length = x;
			missing = 0;
		}		
	}
	if( (counter < (L-1)) && (index == -1) )
	{
		// we have missed fec symbol at boundries of fec block!
		int bound[2], countArray[2], t, count = 0;
		temp = LinearArray[0];
		bound[0] = temp-1;
		temp = LinearArray[length-1];
		bound[1] = temp+1;
		if(dataSymbols[bound[0]].Mark == true)
		{
			sourceBlock->startIndex = bound[0];
			sourceBlock->endIndex   = ((bound[1]-1) + (L*(D-1)))%65536;
		}
		else if(dataSymbols[bound[1]].Mark == true)
		{
			sourceBlock->startIndex = bound[0] + 1;
			sourceBlock->endIndex   = (bound[1] + (L*(D-1)))%65536;
		}
		//printf("[F]startIndex = %d, endIndex = %d\n", sourceBlock->startIndex, sourceBlock->endIndex);
	}
	else if(length == L )
	{
		// we have missed fec symbol in between of array
		sourceBlock->startIndex = LinearArray[0];
		sourceBlock->endIndex   = (LinearArray[length-1] + (L*(D-1)))%65536;
		//printf("[F]startIndex = %d, endIndex = %d\n", sourceBlock->startIndex, sourceBlock->endIndex);
	}
	return 0;
}
void decoder_initialization(struct rte_mbuf *pkt)
{
	uint8_t rows, col;
	struct fec_hdr *fec;
	fec = (struct fec_hdr *)(rte_pktmbuf_mtod(pkt, char *) 
							            + sizeof(struct ether_hdr) 
							            + sizeof(struct ipv4_hdr)
										+ sizeof(struct udp_hdr)
										+ sizeof(struct rtp_hdr));
	col = fec->M;
	rows  = fec->N;
	struct RaptorQ_ptr *enc;
	const uint16_t subsymbol = 64;
	const uint16_t symbol_size = 1320;
	enc = RaptorQ_Enc (ENC_32, NULL, 330*rows, subsymbol, symbol_size, 1320*rows);
	oti_scheme = RaptorQ_OTI_Scheme (enc);
	oti_common = RaptorQ_OTI_Common (enc);
	//printf("col = %d, rows = %d, oti_scheme = %d, oti_common = %llu\n", col, rows, oti_scheme, oti_common);
	L = col;
	D = rows;
	//while(1);
	
}

uint32_t getFecTimeStamp(struct rte_mbuf *pkt)
{
	struct fec_hdr *fec;
	fec = (struct fec_hdr *)(rte_pktmbuf_mtod(pkt, char *) 
							            + sizeof(struct ether_hdr) 
							            + sizeof(struct ipv4_hdr)
										+ sizeof(struct udp_hdr)
										+ sizeof(struct rtp_hdr));
	return(rte_cpu_to_be_32(fec->timeStampRecovery));
}
uint32_t getTimeStamp(struct rte_mbuf *pkt)
{
	struct rtp_hdr *rtp;
	rtp = (struct rtp_hdr *)(rte_pktmbuf_mtod(pkt, char *) 
											+ sizeof(struct ether_hdr) 
											+ sizeof(struct ipv4_hdr)
											+ sizeof(struct udp_hdr));
	return(rte_cpu_to_be_32(rtp->timeStamp));	
}
void setTimeStamp(uint32_t tStamp, struct rte_mbuf *pkt)
{
	struct rtp_hdr *rtp;
	rtp = (struct rtp_hdr *)(rte_pktmbuf_mtod(pkt, char *) 
											+ sizeof(struct ether_hdr) 
											+ sizeof(struct ipv4_hdr)
											+ sizeof(struct udp_hdr));
	rtp->timeStamp = rte_cpu_to_be_32(tStamp);	
}
uint32_t getSynSource(struct rte_mbuf *pkt)
{
	struct rtp_hdr *rtp;
	rtp = (struct rtp_hdr *)(rte_pktmbuf_mtod(pkt, char *) 
											+ sizeof(struct ether_hdr) 
											+ sizeof(struct ipv4_hdr)
											+ sizeof(struct udp_hdr));
	return(rte_cpu_to_be_32(rtp->synSource));	
}
uint8_t getProtocol( struct rte_mbuf *pkt )
{
	struct ipv4_hdr *iph;
	iph = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, char *) + sizeof(struct ether_hdr)); 
	return (iph->next_proto_id);	
}
uint32_t getSourceIp( struct rte_mbuf *pkt )
{
	struct ipv4_hdr *iph;
	iph = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, char *) + sizeof(struct ether_hdr)); 
	return (htonl(iph->src_addr));	
}
uint32_t getDestinationIp( struct rte_mbuf *pkt )
{
	struct ipv4_hdr *iph;
	iph = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, char *) + sizeof(struct ether_hdr)); 
	return (htonl(iph->dst_addr));	
}
void setEtherDestination(struct rte_mbuf *pkt, unsigned lcore_id)
{
	struct ether_hdr *eth_hdr;
	eth_hdr = rte_pktmbuf_mtod(pkt, struct ether_hdr *);
	ether_addr_copy(&eth_hdr->d_addr, &NewAddresses[lcore_id].mc_eth_addr[0]);   //(from _source, to _dest)
	ether_addr_copy(&eth_hdr->s_addr, &NewAddresses[lcore_id].mc_eth_addr[1]);
}
void setDestinationPort(struct rte_mbuf *pkt)
{
	struct udp_hdr *udp;
	struct ipv4_hdr *iph;
	iph = (struct ipv4_hdr *)(rte_pktmbuf_mtod(pkt, char *) + sizeof(struct ether_hdr));
	udp = (struct udp_hdr *)(rte_pktmbuf_mtod(pkt, char *) 
							            + sizeof(struct ether_hdr) 
							            + sizeof(struct ipv4_hdr));
    udp->dst_port    =  htons(7890);
	udp->dgram_cksum =  0;
	iph->hdr_checksum = rte_ipv4_cksum(iph);
}
uint16_t getSourcePort(struct rte_mbuf *pkt)
{
	struct udp_hdr *udp;
	udp = (struct udp_hdr*)((rte_pktmbuf_mtod(pkt, char *)+sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr)));
	return (htons(udp->src_port));
}
uint16_t getDestinationPort(struct rte_mbuf *pkt)
{
	struct udp_hdr *udp;
	udp = (struct udp_hdr*)((rte_pktmbuf_mtod(pkt, char *)+sizeof(struct ether_hdr)+sizeof(struct ipv4_hdr)));
	return (htons(udp->dst_port));
}
////////////////////////////////////////////////////////////////////////
bool packetMbufsSource(struct rte_mbuf **data_pkt, int dataPkt_length)
{
	//printf("A ");
	int count;
	for(count = 0; count < dataPkt_length; count++)
	{
		data_pkt[count] = rte_pktmbuf_alloc(pktmbuf_pool[0]);
		if ( (data_pkt[count] == NULL) ) 
		{
			printf("mbuf allocation for data packets failed\n");
			return false;
		}
		//printf("B ");
	}		   
	return true;
}
void printArray(struct rte_mbuf **pktarr, int regRtpCount)
{
	int n;
	for(n = 0; n<regRtpCount; n++)
		printf("index = %d, seq# %d\n", n, getSequenceNumber(pktarr[n], false));
	printf("==========================================\n");

}
void sortPktArray(struct rte_mbuf **pktarr, int length, bool packetType)
{
	// packetType = false for rtp, true for fec
	//printf("sortPktArray\n");
	//printArray(pktarr, length);
	int x, y;
	struct rte_mbuf *temp;
	for(x = 0; x<length; x++)
	{
		for(y = x+1; y<length; y++)
		{
			if(getSequenceNumber(pktarr[x], packetType) > getSequenceNumber(pktarr[y], packetType))
			{
				temp = pktarr[x];
				pktarr[x] = pktarr[y];
				pktarr[y] = temp;
			}
		}
	}
}
int findBreakIndex(struct rte_mbuf **pktarr, int regRtpCount)
{
	//printArray(pktarr, regRtpCount);
	int x, def = 0;
	for(x = 0; x<(regRtpCount-1); x++)
	{
		def = getSequenceNumber(pktarr[x+1], false) - getSequenceNumber(pktarr[x], false);
		//printf("findBreakIndex def: %d\n", def);
		if(def > 65400)
			return (x);
	}
	return 0;
}
int regStream(struct rte_mbuf **pktarr, int regStart, int regEnd,
			  int breakIndex, int regRtpCount, struct MarkDataSymbols *dataSymbols)
{
//	printf("regStream  breakIndex %d\n", breakIndex);
	int x, temp = 0, ret, index = 0;
	if(breakIndex == 0)
	{
		for(x = 0; x<regRtpCount; x++)
		{
			temp = getSequenceNumber(pktarr[x], false); 
			if( temp >= regStart && temp <= regEnd)
			{
				dataSymbols[temp].Mark = false;
				//printf("sending %d: regStart %d: regEnd %d\n", temp, regStart, regEnd);
				//setDestinationPort(pktarr[x]);
				ret = sendPacketQ(&pktarr[x], 0);
				//ret = rte_eth_tx_burst(1, 0, &pktarr[x], 1);
				//printf("packet sent: %d, ret = %d\n", temp, ret);
				index = x; // index of last packet sent from this array
						   // rest of packets will be added for next block
						   // processing.
			}
		}
	}
	else
	{
		for(x = (breakIndex+1); x<regRtpCount; x++)
		{
			temp = getSequenceNumber(pktarr[x], false); 
			if(temp <= 65535)
			{
				dataSymbols[temp].Mark = false;
				//ret = rte_eth_tx_burst(1, 0, &pktarr[x], 1);
				ret = sendPacketQ(&pktarr[x], 0);
			}
		}
		for(x = 0; x<=regEnd; x++)     // breakIndex is replaced with regEnd
		{
			temp = getSequenceNumber(pktarr[x], false); 
			dataSymbols[temp].Mark = false;
			//ret = rte_eth_tx_burst(1, 0, &pktarr[x], 1);
			ret = sendPacketQ(&pktarr[x], 0);
			index = x;	
		}
		
	}
	//printf("index in fun: %d\n", index);
	
return index;
}
void recoverTimeStamp(int syncPacket, int  element, 
					  struct MarkDataSymbols *dataSymbols, struct MarkFecSymbols *FecSymbols,
					  struct rte_mbuf *rPkt)
{
	int x, temp;
	uint32_t timeStamp, sumTimeStamps = 0;
	temp = syncPacket;
	for(x = 0; x<D; x++)
	{
		if(temp == element)
		{
			if(FecSymbols[syncPacket%1000].pkt == NULL)
				printf("NULL at FEC %d \n", syncPacket);
			timeStamp = getFecTimeStamp(FecSymbols[syncPacket%1000].pkt); // need separate fun
			//printf("fec time %d \n", temp);
			temp = (temp + L)%65536;
			sumTimeStamps = sumTimeStamps^timeStamp;
		}
		else
		{
			if(dataSymbols[temp].pkt == NULL)
				printf("NULL at DS %d \n", temp);
			timeStamp = getTimeStamp(dataSymbols[temp].pkt);
			//printf("data time %d \n", temp);
			temp = (temp + L)%65536;
			sumTimeStamps = sumTimeStamps^timeStamp;
		}
	}
	setTimeStamp(sumTimeStamps, rPkt);
}
//////////////////////////////////////////////////////////////////////////
static int
lcore_hello( )
{
	struct blockIndex sourceBlock;
	//tsr.pTime_stamp = 0;
	//tsr.counter = 0;
	struct rte_mbuf *regPtr;
	struct rte_mbuf *regFecArr[500];  // >> L 
	struct rte_mbuf *regRtpArr[500]; // double of LXD
	int regFecCount = 0, regRtpCount = 0;
	uint16_t regStart = 0, regEnd = 0;
	int fecIndex = 0;
	/////////////////////////////////////////////////
	struct MarkDataSymbols dataSymbols[65536];
	struct MarkFecSymbols  FecSymbols[1001];
	//bool Mark[65536];
	bool MarkFec[1001];
	uint8_t *packetBuffer, *fecBuffer, *recoveryBuffer; 
	packetBuffer = (uint8_t *)rte_malloc("PacketBuffer",  268431360, RTE_CACHE_LINE_SIZE);
	if(packetBuffer == NULL)
	{
		printf("packetBuffer can't allocated\n");
		exit(1);
	}
	else printf("packetBuffer allocated\n");
	fecBuffer = (uint8_t *)rte_malloc(NULL,  2050048, 32);
	if(fecBuffer == NULL)
	{
		printf("fecBuffer can't allocated\n");
		exit(1);
	}
	else printf("fecBuffer allocated\n");
	recoveryBuffer = (uint8_t *)rte_malloc(NULL,  40960, 32);
	// 40960 = 2048 x 20;
	if(recoveryBuffer == NULL)
	{
		printf("recoveryBuffer can't allocated\n");
	}
	else printf("recoveryBuffer allocated\n");
	uint8_t numPackets = 0, type;
	int startBuffer = 0, col = 0, row = 0, totalSym = 0, symbols = 0;
	uint32_t track = 0, index = 0;

	int totalPacketsArrived = 0, minSeqNumber = 65535, curSeqNumber, length = 0;
	int recoveryArray[D], syncPacket;
	bool packetsMiss, decoderInitializationFlag = true;
	int seqArray[100];
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	struct fec_data
	{
		uint16_t sequenceNo;
		uint32_t *ptr;
	};
	struct fec_data fecSymbols[L];
	printf("hello from core %u\n", lcore_id);
	for(int k = 0; k < 65536; k++)
	{
		dataSymbols[k].Mark = false;
		dataSymbols[k].pkt = NULL;
		FecSymbols[k%1000].Mark = false;
		FecSymbols[k%1000].pkt = NULL;
		MarkCopy[k][0] = false;
		MarkCopy[k][1] = false;
		MarkFec[k%1000] = false;
	}
	//printf("&& array filled \n");
	struct rte_mbuf *pktarr[MAX_PKT_BURST];
	int terminate = 1, fecPackets = 0, x = 0;
	int LinearArray[30], NotRecoverable[20], len_linearArray = 0, nlength = 0, recover[20], rec_length = 0;
	int syncPacketArray[20];
	uint16_t maxSeqBase = 0, minSeqBase = 0;
	uint16_t element;
	int xtrafecPacket = 0;
	struct rte_mbuf* successful;
	int blocksDecoded = 0;
	uint64_t timeCalc = 0;
	bool T = false, timerSet = false;
	void *pkts[64];
	while(!force_quit)
	{
		//printf(".+.\n");
		if(lcore_para[lcore_id].worker_rx != NULL)
				numPackets = rte_ring_dequeue_burst(lcore_para[lcore_id].worker_rx, pkts,32, NULL);
		//numPackets = rte_eth_rx_burst(0, 0, pktarr, MAX_PKT_BURST);
			// if receive pkts in burst, must use return variable
			if(numPackets)
			{
				for(int k = 0; k<numPackets; k++)
				{
					pktarr[k] = (struct rte_mbuf *)pkts[k];
					//assignNewIpSourceGroup(pktarr[k], (int)lcore_id);
					if(NewAddresses[lcore_id].set != true)
					{
						NewAddresses[lcore_id].multiCastIp = getDestinationIp(pktarr[x]);
						NewAddresses[lcore_id].udpDestPort = getDestinationPort(pktarr[x]);
						NewAddresses[lcore_id].udpSrcPort = getSourcePort(pktarr[x]);
						NewAddresses[lcore_id].sourceIp    = getSourceIp(pktarr[x]);
						NewAddresses[lcore_id].synSource   = getSynSource(pktarr[x]);
						setEtherDestination(pktarr[x], lcore_id);
						NewAddresses[lcore_id].set = true;
					}
					//printf("Packets received \n");
					//rte_pktmbuf_free(pktarr[k]);
				}
				//numPackets = 0;
			}
			if(numPackets)
			{ 
				//printf("packet received ... %d\n", numPackets);
				
				for(int x = 0; x < numPackets; x++)
				{
					printf("\t\t\tvlan # %d\n", rte_vlan_strip(pktarr[x]));
					rte_timer_manage();
					//printf("packet # ... %d\n", x);
					const uint8_t* data;
					type = packetType(pktarr[x]);     // 0 = rtp, 1 = fec, 2 = other
					if(type == IGMP)
					{
						timerSet = igmpPacket(pktarr[x]);
					}
					else if(type == RTP)
					{
						if(T==false){timeCalc=rte_get_timer_cycles();T=true;}
						data = (uint8_t*) rte_pktmbuf_mtod( pktarr[x], char *) + 
						sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr)+
						sizeof(struct rtp_hdr);
						int headerlength = sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr)+
						sizeof(struct rtp_hdr);
						//printf("tsr.time_stamp = %d\n", tsr.time_stamp);
						regRtpArr[regRtpCount++] = pktarr[x];
						
					}
					else if(type == FEC)
					{
						data = (uint8_t*) rte_pktmbuf_mtod( pktarr[x], char *) + 
						sizeof(struct ether_hdr) + sizeof(struct ipv4_hdr) + sizeof(struct udp_hdr) +
							sizeof(struct rtp_hdr) + sizeof(struct fec_hdr);
						if(decoderInitializationFlag)
						{
							// note that L, D values should be same across all lcores (working decoders)
							// future work ! but simple fix
							decoder_initialization(pktarr[x]);
							decoderInitializationFlag = false;
						}
						//regFecArr[regFecCount++] = pktarr[x];
					}
					
					if(type == RTP)
					{
						
						totalPacketsArrived++;
						uint16_t seq = getSequenceNumber(pktarr[x], false);
						printf("DEBUG: rtp seq# %d\n",seq);
						curSeqNumber = seq;
						dataSymbols[seq].Mark = true;
						dataSymbols[seq].pkt  = pktarr[x];
						index = seq * 2048;
						rte_memcpy ( &packetBuffer[ index ], data, 1320);
						//bufferDisplay(&packetBuffer[index], 1);
						if(minSeqNumber > curSeqNumber)
							minSeqNumber = seq;
						//printf("DEBUG: totalPacketsArrived  %d...\n", totalPacketsArrived);
					}
					else if(type == FEC)
					{
						int k, diff, length2 = 0, tempIndex = 0, LinearArray2[30] = {0};
						fecPackets++;
						//printf("[rtpPackets: %d][ fecPackets:%d ]\n", totalPacketsArrived, fecPackets);
						uint16_t seqBase = getSequenceNumber(pktarr[x], true);
						//printf("[ fec sequence #: %d ]\n", seqBase);
						maxSeqBase = seqBase;
						index = seqBase % 1000;
						//printf("BaseSequenceNo: %d, index: %d\n", seqBase, index);
						FecSymbols[index].Mark = true;
						FecSymbols[index].pkt  = pktarr[x];
						index = index * 2048;
						rte_memcpy ( &fecBuffer[ index ], data, 330*4);
						//bufferDisplay(&fecBuffer[index], 0);
						LinearArray[len_linearArray++] = maxSeqBase;
						xtrafecPacket = maxSeqBase;
						//printf("len_linearArray = %d, maxSeqBase = %d\n", len_linearArray, maxSeqBase);
						// xtrafecPacket: this variable is used bcz we have received [ 0 -> (L-1) + 1 ]
						// fec packets, and its need to be included in next block 
						//printf("[->]maxSeqBase = %d, minSeqBase = %d\n", maxSeqBase, minSeqBase);
						//if( (maxSeqBase - minSeqBase) > 5 ) //(L*D) )
						if( (len_linearArray) > L )
						{	
							//printf("&& decoder activated...\n");
							blocksDecoded++;
							for(k = 0; k<len_linearArray; k++)
							{
								//printf("linearArray[%d] = %d\n", k, LinearArray[k]);
							}
							//printf("==============\n");
							for(k = 0; k<(len_linearArray-1); k++)
							{
								diff = LinearArray[k+1]-LinearArray[k];
								
								if( ((diff >= 1) && (diff < 3)) || ((diff >= -65535) && (diff < -65533)) )  // its is calculated atleast as > 10
								{
									LinearArray2[length2] = LinearArray[length2];
									length2++;
								}
								else
								{
									LinearArray2[length2] = LinearArray[length2];
									length2++;
									break;
								}
							}
							//printf("=============%d\n", length2);
							for(k = 0; k<length2; k++)
							{
								//printf("linearArray2[%d] = %d\n", k, LinearArray2[k]);
							}
							printf("\n");
							for(k = length2; k<len_linearArray; k++)
							{
								LinearArray[tempIndex] = LinearArray[k];
								//printf("LinearArray[%d] = %d\n", tempIndex, LinearArray[tempIndex]);
								tempIndex++;
							}
							len_linearArray = tempIndex;
							tempIndex = 0;
							int status= checkMissingSourceSymbols(		LinearArray2, 
																		length2,       //len_linearArray-1,
																		NotRecoverable,
																		&nlength,
																		recover,
																		syncPacketArray,
																		&rec_length,
																  		dataSymbols,
																  		&sourceBlock
																 );
							//printf("status %d returns\n", status);
							//printf("[rec_length: %d][ NotRecoverable: %d ]\n", rec_length, nlength);
							if(nlength)
							{
								//printf("NotRecoverable:\n");
								for(k = 0; k<nlength; k++)
								{
									//printf("seq #: %d\n", NotRecoverable[k]);
								}
							}
							if(rec_length && (length2 >= (L-1)) )
							{
									
								for(k = 0; k < rec_length; k++)
								{	
									// k should be "k < rec_length", for that we need to send "recoveryBuffer"
									// first and then could start recovery for next packet
									syncPacket = syncPacketArray[k];
									element    = recover[k];
									//printf("----Starting Recovery \nsync %d, element %d \n", syncPacket, element);
									successful = recoverPacket(recoveryBuffer,
															   syncPacket,
															   element, 
														       packetBuffer,
															   fecBuffer,
															   NULL );
									//printf("rec seq#%d\n",getSequenceNumber(successful, false));
									recoverTimeStamp(syncPacket, element, dataSymbols, FecSymbols, successful);
									//printf("RP->seq #: %d, TS = %d\n", element, getTimeStamp(successful));
									regRtpArr[regRtpCount++] = successful;
									
								}
								//printf("deltaTime=%lu\n", rte_get_timer_cycles()-timeCalc);
								//printf("hz = %lu\n", rte_get_timer_hz());
								//while(1);
								//rte_free(recoveryBuffer);
							}
							minSeqBase = 0;
							maxSeqBase = 0;
							//len_linearArray = 0;
							//LinearArray[len_linearArray++] = xtrafecPacket;
							/////////////////////////////////////////////////////////
							int breakIndex = 0, ind = 0, rem = 0, nx;
							regStart = sourceBlock.startIndex;
							regEnd   = sourceBlock.endIndex;
							//printf("regStart = %d, regEnd = %d\n", regStart, regEnd); 
							sortPktArray(regRtpArr, regRtpCount, false);
							breakIndex = findBreakIndex(regRtpArr, regRtpCount);
							//sleep(1);
							rem = regStream(regRtpArr, regStart, regEnd, breakIndex, regRtpCount, dataSymbols);
							//printf("-------------\n");
							//printf("rem = %d\n", rem);
							if(breakIndex == 0)
							{
								for(nx = rem+1; nx<regRtpCount; nx++)
									regRtpArr[ind++] = regRtpArr[nx];
							}
							else
							{
								for(nx = rem+1; nx<=breakIndex; nx++)
									regRtpArr[ind++] = regRtpArr[nx];
							}
							regRtpCount = ind;
							breakIndex  = 0;
							regStart    = 0;
							regEnd      = 0;
							
							
							if(blocksDecoded%100 == 0)
							{
								//gotoxy(0,0);
								printf("Blocks decoded%d\n", blocksDecoded);
							}
							
							
						}
						// since we are recovering time stamps of recovered pkts 
						// we need fec symbols at certain amount and then get them free!!
						regFecArr[fecIndex++] = pktarr[x];
						if(fecIndex > 40)
						{
							int qx, qindex = 0;
							uint16_t sb;
							for(qx = 0; qx < 30; qx++)
							{
								sb = getSequenceNumber(regFecArr[qx], true);
								rte_pktmbuf_free(regFecArr[qx]);
								//FecSymbols[sb%1000].Mark = false;
								//FecSymbols[sb%1000].pkt  = NULL;
							}
							for(qx = 30; qx < fecIndex; qx++)
								regFecArr[qindex++] = regFecArr[qx];
							fecIndex = qindex;
						}
						
						 
					} // end of 2nd else "type == FEC"
					else if(type != IGMP)
						rte_pktmbuf_free(pktarr[x]);
					//printf("ABCD\n");
				}  // end of packet arrival for loop 
			} // end of numPackets if
		/*	if(blocksDecoded%100 == 0)
			{
				//gotoxy(0,0);
				printf("Blocks decoded [ %d ]\n", blocksDecoded);
			}*/
	}
	return 0;
}
static int
main_processing_loop(__attribute__((unused)) void *arg)
{
	int ret;
	unsigned lcore_id;
	lcore_id = rte_lcore_id();
	printf("main_processing_loop launched %u\n", lcore_id);
	if(lcore_id == 0)
	{
		lcore_Distributer();
	}
	else if(lcore_id == 1)
	{
		//lcore_IGMP();
	}
	else if(lcore_id == 2)
	{
		lcore_TX();
	}
	else if (lcore_id == 3)
	{
		lcore_hello();
	}
}
static void
signal_handler(int signum)
{
	if (signum == SIGINT || signum == SIGTERM) {
		printf("\n\nSignal %d received, preparing to exit...\n",
				signum);
		force_quit = true;
	}
}
void gotoxy(int x, int y)
{
	printf("%c[%d;%df", 0x1B, y,x);
}
int
main(int argc, char **argv)
{
	force_quit = false;
	signal(SIGINT, signal_handler);
	signal(SIGTERM, signal_handler);
	uint8_t ret, socketid = 0;
	unsigned lcore_id;
	struct rte_eth_conf port_conf;
	memset(&port_conf,0,sizeof(rte_eth_conf));
	port_conf.rxmode.split_hdr_size = 0;
	port_conf.rxmode.header_split = 0;
	port_conf.rxmode.hw_ip_checksum = 0;
	port_conf.rxmode.hw_vlan_filter = 0;
	port_conf.rxmode.jumbo_frame = 0;
	port_conf.rxmode.hw_strip_crc = 0;
	port_conf.rxmode.mq_mode = ETH_MQ_RX_NONE;
	port_conf.rx_adv_conf.rss_conf.rss_key = NULL,
	port_conf.rx_adv_conf.rss_conf.rss_hf  = ETH_RSS_IP,
	port_conf.txmode.mq_mode = ETH_MQ_TX_NONE,
	

	ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_panic("Cannot init EAL\n");
	argc -= ret;
	argv += ret;
	ret = parse_args(argc, argv);
	/* init memory */
	ret = init_mem(NB_MBUF);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "init_mem failed\n");
	setup_hash(0);
	int ports = 2;
	for(int x = 0; x<ports; x++)
	{
		ret = rte_eth_dev_configure(x, 1, 1, &port_conf);
		if (ret < 0)
				rte_exit(EXIT_FAILURE, "Cannot configure device: err = ?, port = ?\n");
		ret = rte_eth_tx_queue_setup(x, 0, nb_txd, socketid, NULL);
		if(ret == -ENOMEM)
			printf("\nunable to allocate the tx ring descriptors");
		else if (ret < 0)
					rte_exit(EXIT_FAILURE, "rte_eth_tx_queue_setup: err = ? port = ?\n");
		ret = rte_eth_rx_queue_setup(x, 0, nb_rxd, socketid, NULL, pktmbuf_pool[0]);
		if(ret == -ENOMEM)
			printf("\nunable to allocate the rx ring descriptors");
		else if (ret < 0)
					rte_exit(EXIT_FAILURE, "rte_eth_rx_queue_setup: err = ? port = ?\n");
		rte_eth_promiscuous_enable( x );
		/* Start device */
		ret = rte_eth_dev_start( x );
		if (ret < 0)
			rte_exit(EXIT_FAILURE, "rte_eth_dev_start: err = ?, port = ?\n");
	}
	//rte_eth_promiscuous_enable( 0 );
	rte_eth_macaddr_get(1, &ports_eth_addr[0]);     // portId , portId
	print_ethaddr(" src Address:", &ports_eth_addr[0]);
	printf("\n");
	/* call lcore_hello() on every slave lcore */
	RTE_LCORE_FOREACH_SLAVE(lcore_id) {
		rte_eal_remote_launch(main_processing_loop, NULL, lcore_id);
	}

	/* call it on master lcore too */
	main_processing_loop(NULL);

	rte_eal_mp_wait_lcore();
	return 0;
}
