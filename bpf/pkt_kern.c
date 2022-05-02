#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <arpa/inet.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ptrace.h>
#include <bpf/bpf_endian.h>
#include <linux/sched.h>
#include <string.h>
#include <stdio.h>

struct src_dst_comb{
  __u8 src_addr[4],dst_addr[4];
  __u16 dst_port;
  char protocol[3];
};

typedef struct network_addr
{
    char addr[20];
    int pfx;
} network_addr_t;

typedef struct bpf_lpm_trie_key bpf_lpm_trie_key_t;

struct bpf_map_def SEC("maps") pkt_cnt = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct src_dst_comb),
	.value_size = sizeof(__u32),
	.max_entries = 1000,
};

struct bpf_map_def SEC("maps") pkt_drop = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = sizeof(struct src_dst_comb),
	.value_size = sizeof(__u32),
	.max_entries = 1000,
};

struct bpf_map_def SEC("maps") subnet_configs = {
	.type = BPF_MAP_TYPE_LPM_TRIE,
	.key_size = sizeof(__u32) + sizeof(__u8),
	.value_size = sizeof(__u32),
	.max_entries = 100,
};

struct bpf_map_def SEC("maps") vip_configs = {
	.type = BPF_MAP_TYPE_HASH_OF_MAPS,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 100,
};


SEC("xdp")
int xdp_traffic_pass(struct xdp_md *ctx) {
  struct src_dst_comb src_dst = {};
  uint16_t h_proto;

  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;

  if (data + sizeof(*eth) > data_end)
    return XDP_DROP;

  h_proto = eth->h_proto;

  struct iphdr *iph = data + sizeof(struct ethhdr);
  if (iph + 1 > data_end)
      return XDP_PASS;

  if (h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  src_dst.src_addr[0] = iph->saddr & 0xFF;
  src_dst.src_addr[1] = (iph->saddr >> 8) & 0xFF;
  src_dst.src_addr[2] = (iph->saddr >> 16) & 0xFF;
  src_dst.src_addr[3] = (iph->saddr >> 24) & 0xFF;

  src_dst.dst_addr[0] = iph->daddr & 0xFF;
  src_dst.dst_addr[1] = (iph->daddr >> 8) & 0xFF;
  src_dst.dst_addr[2] = (iph->daddr >> 16) & 0xFF;
  src_dst.dst_addr[3] = (iph->daddr >> 24) & 0xFF;

  if(iph->protocol == IPPROTO_UDP){
    struct udphdr *udph = (struct udphdr *)(iph + 1);
      if (udph + 1 > data_end)
          return XDP_PASS;
    src_dst.dst_port = bpf_ntohs(udph->dest);
    strcpy(src_dst.protocol,"udp");
  }else{
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
      if (tcph + 1 > data_end)
          return XDP_PASS;
    src_dst.dst_port = bpf_ntohs(tcph->dest);
    strcpy(src_dst.protocol,"tcp");
  }

  int *check =  bpf_map_lookup_elem(&allowed_src_dst,&src_dst);
  if(check){
    char str[] = "Got a match by fd %d";
    bpf_trace_printk(str, sizeof(str), *check);

    __u32 *pkt_val = bpf_map_lookup_elem(&pkt_drop,&src_dst);
    __u32 pkt_count = 0;
    if (!pkt_val) {
      bpf_map_update_elem(&pkt_drop, &src_dst, &pkt_count, BPF_ANY);
    } else {
      pkt_count = (*pkt_val) + 1;
      bpf_map_update_elem(&pkt_drop, &src_dst, &pkt_count, BPF_ANY);
     }
    return XDP_DROP;
  } else {
    __u32 *pkt_val = bpf_map_lookup_elem(&pkt_cnt,&src_dst);
    __u32 pkt_count = 0;
    if (!pkt_val) {
      bpf_map_update_elem(&pkt_cnt, &src_dst, &pkt_count, BPF_ANY);
    } else {
      pkt_count = (*pkt_val) + 1;
      bpf_map_update_elem(&pkt_cnt, &src_dst, &pkt_count, BPF_ANY);
     }
  }

  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
