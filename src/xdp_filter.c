// xdp_filter.c
// Programme XDP/eBPF : filtrage à la vitesse de la carte réseau (Wire-Speed)
// - Consulte la BPF Map "blacklist" : si l'IP source y figure -> XDP_DROP
// - Sinon, incrémente le compteur de paquets de l'IP source dans "ip_stats"
//   (ces stats seront lues par ai_engine.py pour la détection d'anomalies)
//
// Compilation (sur le routeur, dans le conteneur xdp-router) :
//   clang -O2 -g -target bpf -c xdp_filter.c -o xdp_filter.o
//
// Attachement à l'interface d'entrée (ex: eth1, côté attaquant) :
//   ip link set dev eth1 xdp obj xdp_filter.o sec xdp
//
// Détachement :
//   ip link set dev eth1 xdp off

#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// ------------------------------------------------------------------
// BPF Maps partagées avec l'espace utilisateur (ai_engine.py)
// ------------------------------------------------------------------

// blacklist : IP source (network byte order) -> 1 si bloquée
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u8);
} blacklist SEC(".maps");

// ip_stats : IP source (network byte order) -> nombre de paquets reçus
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u32);
    __type(value, __u64);
} ip_stats SEC(".maps");

// ------------------------------------------------------------------
// Programme XDP principal
// ------------------------------------------------------------------
SEC("xdp")
int xdp_filter_prog(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // 1. Parser l'en-tête Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS; // paquet tronqué, on laisse passer la pile normale gérer

    // On ne traite que le trafic IPv4
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Parser l'en-tête IP
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    __u32 src_ip = ip->saddr;

    // 3. Consultation de la blacklist : si l'IP y figure -> DROP immédiat
    __u8 *blocked = bpf_map_lookup_elem(&blacklist, &src_ip);
    if (blocked && *blocked == 1) {
        return XDP_DROP;
    }

    // 4. Comptage du trafic par IP source (pour l'analyse IA en espace utilisateur)
    __u64 *count = bpf_map_lookup_elem(&ip_stats, &src_ip);
    if (count) {
        __sync_fetch_and_add(count, 1);
    } else {
        __u64 initial = 1;
        bpf_map_update_elem(&ip_stats, &src_ip, &initial, BPF_ANY);
    }

    // 5. Paquet légitime (ou pas encore classifié) : on laisse passer
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
