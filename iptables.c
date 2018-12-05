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
 * nf_router.c - route packets based on the provided config.
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
#include <rte_arp.h>
#include <rte_tcp.h>
#include <rte_udp.h>
#include <rte_malloc.h>

#include "onvm_nflib.h"
#include "onvm_pkt_helper.h"

#define NF_TAG "iptables"

/* Struct that contains information about this NF */
struct onvm_nf_info *nf_info;

/* number of package between each print */
static uint32_t print_delay = 1000000;

static uint32_t destination;

static uint8_t log_flag=0; 

/*
 * Print a usage message
 */
static void
usage(const char *progname) {
        printf("Usage: %s [EAL args] -- [NF_LIB args] -- -d <destination> -p <print_delay>\n\n", progname);
}


/*
 * Parse the application arguments. iptables command argument.
 */

static int
parse_app_args(int argc, char *argv[], const char *progname) {
        return optind;
}

/*
 * Set log flag according ip protocol number
 */
static void 
raw(struct rte_mbuf* pkt){
	
}

static void

static int
packet_handler(struct rte_mbuf* pkt, struct onvm_pkt_meta* meta) {
       
        struct ether_hdr *eth_hdr;
        //struct arp_hdr *arp_hdr;
        struct ipv4_hdr* ip;
        struct udp_hdr* udp;
        struct tcp_hdr* tcp;

        ip = onvm_pkt_ipv4_hdr(pkt);

        /* If the packet doesn't have an IP header check if its an ARP, if so fwd it to the matched NF */
        if (ip == NULL) {
                eth_hdr = onvm_pkt_ether_hdr(pkt);
                if (rte_cpu_to_be_16(eth_hdr->ether_type) == ETHER_TYPE_ARP) {
                	meta->destination = destination;
                    meta->action = ONVM_NF_ACTION_TONF;
                }
                // other protocol drop
                meta->action = ONVM_NF_ACTION_DROP;
                meta->destination = 0;
                return 0;
        }
        else{
        	if(ip->next_proto_id==17){ // udp

        		udp=onvm_pkt_udp_hdr(pkt);

        		// prerouting vs output (srcip)

        		// input vs forward (dstip)

        		// forward

        		//

        	}
        	else{
        		if(ip->next_proto_id==6){ // tcp
        			tcp=onvm_pkt_tcp_hdr(pkt);
        		}
        		else{	// other protocol forward
        			meta->destination = destination;
                    meta->action = ONVM_NF_ACTION_TONF;
        		}
        	}
        }
        meta->action = ONVM_NF_ACTION_DROP;
        meta->destination = 0;
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
        parse_router_config();

        onvm_nflib_run(nf_info, &packet_handler);
        printf("If we reach here, program is ending\n");
        return 0;
}
