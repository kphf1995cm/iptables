/*********************************************************************
 *                     openNetVM
 *              https://sdnfv.github.io
 *
 *   BSD LICENSE
 *
 *   Copyright(c)
 *            2015-2017 George Washington University
 *            2015-2017 University of California Riverside
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
 *     * The name of the author may not be used to endorse or promote
 *       products derived from this software without specific prior
 *       written permission.
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
 *
 * iptables.c - an example using onvm. Forwards packets to a DST NF.
 ********************************************************************/

#include <unistd.h>
#include <stdint.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdarg.h>
#include <errno.h>
#include <sys/queue.h>
#include <stdlib.h>
#include <getopt.h>
#include <string.h>

#include <rte_common.h>
#include <rte_mbuf.h>
#include <rte_ip.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "iptables"

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 1000000;

/*forward nf*/
static uint32_t destination;

/* packet print flag */
static uint8_t log_flag=0; 

/* host IP destination*/
static uint32_t host_ip=318767115; //(11.0.0.19)

/*raw table: ip protol determine flag */
struct raw_protocol_flag{
	uint8_t protocol;
	uint8_t flag;
};

uint8_t raw_count=3;
struct raw_protocol_flag raw_ptl_flag[3];

static void 
init_raw(void){
	//raw_ptl_flag=(struct raw_protocol_flag* )rte_malloc("raw_ptl_flag", sizeof(struct raw_protocol_flag) * raw_count, 0);
	//raw_ptl_flag=new raw_protocol_flag[raw_count];
	/*if(raw_ptl_flag==NULL){
		 rte_exit(EXIT_FAILURE, "Malloc failed, can't allocate raw_ptl_flag array\n");
	}*/
	raw_ptl_flag[0].protocol=17; //udp
	raw_ptl_flag[0].flag=1;
	raw_ptl_flag[1].protocol=6; //tcp
	raw_ptl_flag[1].flag=1;
	raw_ptl_flag[2].protocol=0; //other
	raw_ptl_flag[2].flag=0;
}

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage: %s [EAL args] -- [NF_LIB args] -- -d <destination> -p <print_delay>\n\n", progname);
}

/*
 * Parse the application arguments.
 */
static int
parse_app_args(int argc, char *argv[], const char *progname) {
        int c, dst_flag = 0;

        while ((c = getopt(argc, argv, "d:p:")) != -1) {
                switch (c) {
                case 'd':
                        destination = strtoul(optarg, NULL, 10);
                        dst_flag = 1;
                        break;
                case 'p':
                        print_delay = strtoul(optarg, NULL, 10);
                        break;
                case '?':
                        usage(progname);
                        if (optopt == 'd')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (optopt == 'p')
                                RTE_LOG(INFO, APP, "Option -%c requires an argument.\n", optopt);
                        else if (isprint(optopt))
                                RTE_LOG(INFO, APP, "Unknown option `-%c'.\n", optopt);
                        else
                                RTE_LOG(INFO, APP, "Unknown option character `\\x%x'.\n", optopt);
                        return -1;
                default:
                        usage(progname);
                        return -1;
                }
        }

        if (!dst_flag) {
                RTE_LOG(INFO, APP, "Simple Forward NF requires destination flag -d.\n");
                return -1;
        }

        return optind;
}

/*
 * This function displays stats. It uses ANSI terminal codes to clear
 * screen when called. It is called from a single non-master
 * thread in the server process, when the process is run with more
 * than one lcore enabled.
 */
static void
do_stats_display(struct rte_mbuf* pkt) {
        const char clr[] = { 27, '[', '2', 'J', '\0' };
        const char topLeft[] = { 27, '[', '1', ';', '1', 'H', '\0' };
        static uint64_t pkt_process = 0;
        struct ipv4_hdr* ip;

        pkt_process += print_delay;

        /* Clear screen and move to top left */
        printf("%s%s", clr, topLeft);

        printf("PACKETS\n");
        printf("-----\n");
        printf("Port : %d\n", pkt->port);
        printf("Size : %d\n", pkt->pkt_len);
        printf("N°   : %"PRIu64"\n", pkt_process);
        printf("\n\n");

        ip = onvm_pkt_ipv4_hdr(pkt);
        if (ip != NULL&&log_flag==1) {
                onvm_pkt_print(pkt);
        } else {
                printf("No IP4 header found\n");
        }
}

static void 
raw(struct rte_mbuf* pkt){

	//printf("come to raw\n");
	struct ipv4_hdr* ip;
	ip=onvm_pkt_ipv4_hdr(pkt);
	uint8_t protocol=ip->next_proto_id;
	//printf("protocol:%d\n",protocol);
	int i; 
	for(i=0;i<raw_count;i++)
	{
		if(protocol==raw_ptl_flag[i].protocol)
		{
			//printf("match protocol\n");
			log_flag=raw_ptl_flag[i].flag;
			break;
		}

	}

}

/*
static void
mangle(struct rte_mbuf* pkt){

}

static void
nat(struct rte_mbuf* pkt){

}

static void
filter(struct rte_mbuf* pkt){

}
*/

static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {

	struct ipv4_hdr* ip;

    static uint32_t counter = 0;
    if (++counter == print_delay) {
        do_stats_display(pkt);
        counter = 0;
    }
	
	//onvm_pkt_print(pkt);
	ip=onvm_pkt_ipv4_hdr(pkt);

	if(ip!=NULL){

		//printf("src ip:%d\n",ip->src_addr);
		if (ip->src_addr == host_ip){ // host send packet
			
			/*output chain*/
			//printf("output chain\n");
			/*postrouting chain*/
		}
		else { // host receive packet
			
			//printf("prerouting chain\n");
			/*prerouting chain*/

			// raw table
			raw(pkt);
		}


	}
		

    meta->action = ONVM_NF_ACTION_TONF;
    meta->destination = destination;
    return 0;
}


int main(int argc, char *argv[]) {
        int arg_offset;

        const char *progname = argv[0];

        if ((arg_offset = onvm_nflib_init(argc, argv, NF_TAG)) < 0)
                return -1;
        argc -= arg_offset;
        argv += arg_offset;

        if (parse_app_args(argc, argv, progname) < 0) {
                onvm_nflib_stop();
                rte_exit(EXIT_FAILURE, "Invalid command-line arguments\n");
        }
        init_raw();
        onvm_nflib_run(nf_info, &packet_handler);
        printf("If we reach here, program is ending\n");
        return 0;
}

