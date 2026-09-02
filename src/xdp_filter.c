// xdp_filter.c
// Programme XDP/eBPF (style BCC) : filtrage à la vitesse de la carte réseau.
// Ce fichier est compilé et chargé DYNAMIQUEMENT par ai_engine.py via bcc
// (BPF(src_file="xdp_filter.c")) -- il n'est PAS compilé à part avec clang.
//
// - Consulte la table "blacklist" : si l'IP source y figure -> XDP_DROP
// - Sinon, incrémente le compteur de paquets de l'IP source dans "ip_stats"
//   (lu périodiquement par ai_engine.py pour la détection d'anomalies)

#include <uapi/linux/bpf.h>
#include <uapi/linux/if_ether.h>
#include <uapi/linux/ip.h>
#include <uapi/linux/in.h>

// ------------------------------------------------------------------
// BPF Maps (macros BCC) partagées avec l'espace utilisateur
// ------------------------------------------------------------------
BPF_HASH(blacklist, u32, u8, 65536);   // IP source -> 1 si bloquée
BPF_HASH(ip_stats, u32, u64, 65536);   // IP source -> nb de paquets reçus

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
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;

    u32 src_ip = ip->saddr;

    // 3. Consultation de la blacklist : DROP immédiat si l'IP y figure
    u8 *blocked = blacklist.lookup(&src_ip);
    if (blocked != 0 && *blocked == 1) {
        return XDP_DROP;
    }

    // 4. Comptage du trafic par IP source (pour l'analyse IA)
    u64 *count = ip_stats.lookup(&src_ip);
    if (count != 0) {
        lock_xadd(count, 1);  // incrément atomique (helper fourni par bcc)
    } else {
        u64 init_val = 1;
        ip_stats.update(&src_ip, &init_val);
    }

    // 5. Paquet légitime (ou pas encore classifié) : on laisse passer
    return XDP_PASS;
}
