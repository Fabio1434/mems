// xdp_filter.c
// Programme XDP/eBPF (style BCC) : filtrage à la vitesse de la carte réseau
// + collecte de métriques MULTI-CRITÈRES par IP source (TCP ET UDP), pour
// permettre à ai_engine.py de détecter des signatures d'attaque fines
// (SYN flood, UDP flood, comportement distribué) au-delà d'un simple débit.
//
// Les tables utilisent le type LRU ("lru_hash") plutôt que "hash" fixe,
// pour rester robustes sous une attaque réelle avec IP source usurpées en
// masse (voir commentaire sur les BPF Maps ci-dessous).
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
// Ces compteurs permettent de dériver, côté IA (ai_engine.py) :
//   - le débit (paquets/seconde)                   -> pps
//   - le ratio de paquets SYN sans ACK               -> syn_ratio
//     (signature typique d'un SYN flood : proche de 1.0)
//   - le ratio de paquets UDP                        -> udp_ratio
//     (signature typique d'un UDP flood : proche de 1.0 alors que le
//      trafic légitime est très majoritairement TCP dans la plupart
//      des contextes applicatifs)
//   - la taille moyenne des paquets                  -> avg_pkt_size
// ------------------------------------------------------------------
struct ip_stat_t {
    u64 packets;
    u64 bytes;
    u64 syn_count;
    u64 udp_count;
};

// ------------------------------------------------------------------
// BPF Maps (macros BCC) partagées avec l'espace utilisateur
//
// Type "lru_hash" plutôt que "hash" standard : sous une attaque réelle
// avec des IP source massivement usurpées (spoofing), une table de taille
// fixe peut se remplir et rejeter silencieusement les nouvelles entrées
// (bpf_map_update_elem échoue sans avertissement visible). Le type LRU
// évince automatiquement les entrées les moins récemment utilisées,
// garantissant que le système continue de fonctionner sous forte charge
// plutôt que de "geler" une fois la table pleine.
// ------------------------------------------------------------------
BPF_TABLE("lru_hash", u32, u8, blacklist, 65536);              // IP source -> 1 si bloquée
BPF_TABLE("lru_hash", u32, struct ip_stat_t, ip_stats, 65536); // IP source -> statistiques

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
    // en-tête IP sans options (IHL = 5, soit 20 octets).
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
    u8 is_udp = 0;

    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)ip + sizeof(*ip);
        if ((void *)(tcp + 1) <= data_end) {
            if (tcp->syn && !tcp->ack) {
                is_syn_only = 1;
            }
        }
    } else if (ip->protocol == IPPROTO_UDP) {
        is_udp = 1;
    }

    // 5. Mise à jour des statistiques multi-critères par IP source
    struct ip_stat_t *stat = ip_stats.lookup(&src_ip);
    if (stat != 0) {
        lock_xadd(&stat->packets, 1);
        lock_xadd(&stat->bytes, pkt_len);
        if (is_syn_only) {
            lock_xadd(&stat->syn_count, 1);
        }
        if (is_udp) {
            lock_xadd(&stat->udp_count, 1);
        }
    } else {
        struct ip_stat_t init_stat = {};
        init_stat.packets = 1;
        init_stat.bytes = pkt_len;
        init_stat.syn_count = is_syn_only ? 1 : 0;
        init_stat.udp_count = is_udp ? 1 : 0;
        ip_stats.update(&src_ip, &init_stat);
    }

    // 6. Paquet légitime (ou pas encore classifié) : on laisse passer
    return XDP_PASS;
}
