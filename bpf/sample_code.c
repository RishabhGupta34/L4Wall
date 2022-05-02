#include <linux/bpf.h>
//#include <bpf/libbpf.h>
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

//#ifndef __BPF_ENDIAN__
//#define __BPF_ENDIAN__
//
//#include <linux/swab.h>
//#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
//# define __bpf_ntohs(x)__builtin_bswap16(x)
//# define __bpf_htons(x)__builtin_bswap16(x)
//# define __bpf_constant_ntohs(x)___constant_swab16(x)
//# define __bpf_constant_htons(x)___constant_swab16(x)
//# define __bpf_ntohl(x)__builtin_bswap32(x)
//# define __bpf_htonl(x)__builtin_bswap32(x)
//# define __bpf_constant_ntohl(x)___constant_swab32(x)
//# define __bpf_constant_htonl(x)___constant_swab32(x)
//#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
//# define __bpf_ntohs(x)(x)
//# define __bpf_htons(x)(x)
//# define __bpf_constant_ntohs(x)(x)
//# define __bpf_constant_htons(x)(x)
//# define __bpf_ntohl(x)(x)
//# define __bpf_htonl(x)(x)
//# define __bpf_constant_ntohl(x)(x)
//# define __bpf_constant_htonl(x)(x)
//#else
//# error "Fix your compiler's __BYTE_ORDER__?!"
//#endif
//
//#define bpf_htons(x)\
//  (__builtin_constant_p(x) ?\
//   __bpf_constant_htons(x) : __bpf_htons(x))
//#define bpf_ntohs(x)\
//  (__builtin_constant_p(x) ?\
//   __bpf_constant_ntohs(x) : __bpf_ntohs(x))
//#define bpf_htonl(x)\
//  (__builtin_constant_p(x) ?\
//   __bpf_constant_htonl(x) : __bpf_htonl(x))
//#define bpf_ntohl(x)\
//  (__builtin_constant_p(x) ?\
//   __bpf_constant_ntohl(x) : __bpf_ntohl(x))
//
//#endif /* __BPF_ENDIAN__ */

//#define PIN_GLOBAL_NS   2

struct data_t{
    __u64 ts;
    __u16 sport, dport;
    char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];
    char protocol[3];
};

struct ip_data{
  __u8 addr[4];
//  __u16 port;
  char protocol[3];
};

struct src_dst_comb{
  __u8 src_addr[4],dst_addr[4];
  __u16 dst_port;
  char protocol[3];
};
//struct src_dst_comb{
//  struct ip_data src,dst;
//};

struct bpf_map_def SEC("maps") src_ips_map = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(struct ip_data),
	.value_size = sizeof(__u32),
	.max_entries = 100,
};

//struct inner_map {
//          __uint(type, BPF_MAP_TYPE_ARRAY);
//          __uint(max_entries, 1);
//          __type(key, int);
//          __type(value, int);
//  } inner_map1 SEC(".maps"),
//    inner_map2 SEC(".maps");

//  struct outer_hash {
//          __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
//          __uint(max_entries, 5);
//          __uint(key_size, sizeof(int));
//          __inner(values, struct inner_map);
//  }

struct bpf_map_def SEC("maps") allowed_src_dst = {
	.type = BPF_MAP_TYPE_HASH,
	.key_size = 13,
	.value_size = sizeof(__u32),
	.max_entries = 100,
};
//
//BPF_HASH_OF_MAPS(allowed_src_dst,struct ip_data, "inner_map", 10);
//struct {
//  __uint(type, BPF_MAP_TYPE_HASH_OF_MAPS);
//  __uint(key_size, sizeof(struct ip_data));
//  __uint(value_size,sizeof(__u32));
//  __uint(max_entries, 100);
//  __type(inner_map_name, "inner_map");
//} allowed_src_dst SEC("maps");


struct bpf_map_def SEC("maps") dst_ips_map = {
	.type = BPF_MAP_TYPE_PERCPU_HASH,
	.key_size = sizeof(struct ip_data),
	.value_size = sizeof(__u32),
	.max_entries = 100,
};

SEC("xdp")
int xdp_traffic_pass(struct xdp_md *ctx) {
//  char str1[] = "sizeof: %d\n";
//  bpf_trace_printk(str1, sizeof(str1), sizeof(struct ip_data));

//  struct data_t event = {};
//  struct ip_data src_ip = {};
//  struct ip_data dst_ip = {};
  struct src_dst_comb src_dst = {};
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct ethhdr *eth = data;

  uint16_t h_proto;

  if (data + sizeof(*eth) > data_end)
    return XDP_DROP;

  h_proto = eth->h_proto;

  struct iphdr *iph = data + sizeof(struct ethhdr);
  if (iph + 1 > data_end)
      return XDP_PASS;

  if (h_proto != bpf_htons(ETH_P_IP)) {
    return XDP_PASS;
  }

//  struct sockaddr_in ip_saddr, ip_daddr;
//  char saddr[INET_ADDRSTRLEN], daddr[INET_ADDRSTRLEN];
//  ip_saddr.sin_addr.s_addr = bpf_ntohs(iph->saddr);
//  ip_daddr.sin_addr.s_addr = bpf_ntohs(iph->daddr);
//  inet_ntop(AF_INET, &(ip_saddr.sin_addr), saddr, INET_ADDRSTRLEN);
//  inet_ntop(AF_INET, &(ip_daddr.sin_addr), daddr, INET_ADDRSTRLEN);

//  src_ip.addr[0] = iph->saddr & 0xFF;
//  src_ip.addr[1] = (iph->saddr >> 8) & 0xFF;
//  src_ip.addr[2] = (iph->saddr >> 16) & 0xFF;
//  src_ip.addr[3] = (iph->saddr >> 24) & 0xFF;
//
//  dst_ip.addr[0] = iph->daddr & 0xFF;
//  dst_ip.addr[1] = (iph->daddr >> 8) & 0xFF;
//  dst_ip.addr[2] = (iph->daddr >> 16) & 0xFF;
//  dst_ip.addr[3] = (iph->daddr >> 24) & 0xFF;

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
//    src_ip.port = bpf_ntohs(udph->source);
//    dst_ip.port = bpf_ntohs(udph->dest);
//    strcpy(src_ip.protocol,"udp");
//    strcpy(dst_ip.protocol,"udp");

//    src_dst.src_port = bpf_ntohs(udph->source);
    src_dst.dst_port = bpf_ntohs(udph->dest);
    strcpy(src_dst.protocol,"udp");
  }else{
    struct tcphdr *tcph = (struct tcphdr *)(iph + 1);
      if (tcph + 1 > data_end)
          return XDP_PASS;
//    src_ip.port = bpf_ntohs(tcph->source);
//    dst_ip.port = bpf_ntohs(tcph->dest);
//    strcpy(src_ip.protocol,"tcp");
//    strcpy(dst_ip.protocol,"tcp");

//    src_dst.src_port = bpf_ntohs(tcph->source);
    src_dst.dst_port = bpf_ntohs(tcph->dest);
    strcpy(src_dst.protocol,"tcp");
//    if (dst_ip.port == 1234){
//      char str1[] = "src port: %d %d %d\n";
//      bpf_trace_printk(str1, sizeof(str1), src_ip.addr[3], src_ip.port,tcph->source);
//    }
  }

//  __u32 *src_val = bpf_map_lookup_elem(&src_ips_map,&src_ip);
//  __u32 src_count = 0;
//  if (!src_val) {
//    bpf_map_update_elem(&src_ips_map, &src_ip, &src_count, BPF_ANY);
//  } else {
//    src_count = (*src_val) + 1;
//    bpf_map_update_elem(&src_ips_map, &src_ip, &src_count, BPF_ANY);
//   }
//
//  __u32 *dst_val =  bpf_map_lookup_elem(&dst_ips_map,&dst_ip);
//  __u32 dst_count = 0;
//  if (!dst_val) {
//    bpf_map_update_elem(&dst_ips_map, &dst_ip, &dst_count, BPF_ANY);
//  } else {
//    dst_count = (*dst_val) + 1;
//    bpf_map_update_elem(&dst_ips_map, &dst_ip, &dst_count, BPF_ANY);
//  }
//  src_dst.src = src_ip;
//  src_dst.dst = dst_ip;
  int *check =  bpf_map_lookup_elem(&allowed_src_dst,&src_dst);
  if(check){
//      __u32 fd = *check_fd;
//    int inner_map_fd = bpf_map_get_fd_by_id(check_id);
    char str[] = "Got a match by fd %d";
    bpf_trace_printk(str, sizeof(str), *check);
//    __u32 check;
//    bpf_map_lookup_elem(*check_fd,&dst_ip,&check);
//    if(check){
//          char str1[] = "Got a match %d";
//          bpf_trace_printk(str1, sizeof(str1), check);
//    }
  }

//  if (dst_ip.port == 1234){
//    char str[] = "src count: %d dst count: %d";
//    bpf_trace_printk(str, sizeof(str), src_count, dst_count);
//    char str1[] = "src port: %d %d %d\n";
//    bpf_trace_printk(str1, sizeof(str1), src_ip.addr[3], src_ip.port,tcph->source);
//    char str2[] = "src ip: %d.%d\n";
//    bpf_trace_printk(str2, sizeof(str2), src_ip.addr[0], src_ip.addr[1]);
//    char str3[] = "src ip: .%d.%d\n";
//    bpf_trace_printk(str3, sizeof(str3), src_ip.addr[2], src_ip.addr[3]);
//  }
//  if (event.dport == 1234){
//    char str[] = "Dropped! Dest IP: %d %d %d %d";
//    char fmt_str[256];
//    snprintf(fmt_str, sizeof(fmt_str), str,bytes[0],bytes[1],bytes[2],bytes[3]);
//    bpf_trace_printk(fmt_str, sizeof(fmt_str));
//    return XDP_DROP;
//  }
//  event.ts = bpf_ktime_get_ns();

//  events.perf_submit(ctx,&event,sizeof(data));

//  if (h_proto == bpf_htons(ETH_P_IPV6)) {
//    bpf_printk("Hello World");
//    value = bpf_map_lookup_elem(&pkt_drops,&key);
//    if(value)
//      *value += 1;
//    return XDP_DROP;
//  }
  return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
