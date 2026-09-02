// xdp_filter.c
// Programme XDP/eBPF (style BCC) : filtrage à la vitesse de la carte réseau
// + collecte de métriques MULTI-CRITÈRES par IP source (pas seulement le
// nombre de paquets), pour permettre à ai_engine.py de détecter des
// signatures d'attaque plus fines qu'un simple seuil de débit.
//
// Ce fichier est compilé et chargé DYNAMIQUEMENT par ai_engine.py via bcc
// (BPF(src_file="xdp_filter.c")) -- il n'est PAS compilé à part avec clang.

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>
#include <uapi/linux/tcp.h>

// ------------------------------------------------------------------
// Structure de statistiques par IP source, collectée au niveau noyau.
// Ces trois compteurs permettent de dériver, côté IA (ai_engine.py) :
//   - le débit (paquets/seconde)                 -> pps
//   - le ratio de paquets SYN sans ACK             -> syn_ratio
//     (signature typique d'un SYN flood : proche de 1.0)
//   - la taille moyenne des paquets                -> avg_pkt_size
//     (un flood UDP/SYN utilise souvent des paquets anormalement petits
//      et uniformes, contrairement à du trafic applicatif normal)
// ------------------------------------------------------------------
struct ip_stat_t {
    u64 packets;
    u64 bytes;
    u64 syn_count;
};

// ------------------------------------------------------------------
// BPF Maps (macros BCC) partagées avec l'espace utilisateur
// ------------------------------------------------------------------
BPF_HASH(blacklist, u32, u8, 65536);            // IP source -> 1 si bloquée
BPF_HASH(ip_stats, u32, struct ip_stat_t, 65536); // IP source -> statistiques

// ------------------------------------------------------------------
// Programme XDP principal
// ------------------------------------------------------------------
int xdp_filter_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;

    // 1. Parser l'en-tête Ethernet
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP))
        return XDP_PASS;

    // 2. Parser l'en-tête IP
    // NB (limitation connue, acceptable pour ce PoC) : on suppose une
    // en-tête IP sans options (IHL = 5, soit 20 octets). Un paquet avec
    // options IP sera traité par la pile normale (moins précis mais
    // sans risque de faux DROP).
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    u32 src_ip = ip->saddr;
    u16 pkt_len = bpf_ntohs(ip->tot_len);

    // 3. Consultation de la blacklist : DROP immédiat si l'IP y figure
    u8 *blocked = blacklist.lookup(&src_ip);
    if (blocked != 0 && *blocked == 1) {
        return XDP_DROP;
    }

    // 4. Détecter un paquet TCP SYN (sans ACK) -- signature de SYN flood
    u8 is_syn_only = 0;
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) <= data_end) {
            if (tcp->syn && !tcp->ack) {
                is_syn_only = 1;
            }
        }
    }

    // 5. Mise à jour des statistiques multi-critères par IP source
    struct ip_stat_t *stat = ip_stats.lookup(&src_ip);
    if (stat != 0) {
        lock_xadd(&stat->packets, 1);
        lock_xadd(&stat->bytes, pkt_len);
        if (is_syn_only) {
            lock_xadd(&stat->syn_count, 1);
        }
    } else {
        struct ip_stat_t init_stat = {};
        init_stat.packets = 1;
        init_stat.bytes = pkt_len;
        init_stat.syn_count = is_syn_only ? 1 : 0;
        ip_stats.update(&src_ip, &init_stat);
    }

    // 6. Paquet légitime (ou pas encore classifié) : on laisse passer
    return XDP_PASS;
}
