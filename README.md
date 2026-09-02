# Détection et neutralisation automatisée des cyberattaques à haute vitesse
### Mémoire de Master 2 — Télécommunications & Cybersécurité

Sécurisation des infrastructures télécoms à très haut débit via **eBPF/XDP** et **Intelligence Artificielle** (Isolation Forest).

## 1. Contexte

Les systèmes de protection réseau traditionnels (firewalls applicatifs, IDS/IPS comme Suricata/Snort, iptables) montrent leurs limites sur des liens à 10–100 Gbps : chaque paquet doit remonter la pile réseau du noyau avant d'être analysé en espace utilisateur, ce qui sature le CPU lors d'attaques DDoS massives.

Ce projet propose une architecture hybride qui filtre le trafic **à la vitesse de la carte réseau** grâce à eBPF/XDP, pilotée dynamiquement par un moteur d'IA léger (Isolation Forest) qui détecte les anomalies de trafic et met à jour les règles de blocage en temps réel.

## 2. Architecture

```
                    ┌─────────────────────────────┐
                    │        xdp-router           │
  [attacker] ──eth1─┤  eth1 (XDP attaché)          │
                    │   │                          │
                    │   ├─ BPF Map "blacklist"      │◄── écrite par ai_engine.py
                    │   ├─ BPF Map "ip_stats"        │──► lue par ai_engine.py
                    │   │                          │
  [legit-client] ─eth2─┤ eth2                        │
                    │   eth3 ──────────────────────┼──eth1── [target-server]
                    └─────────────────────────────┘
```

- **Espace noyau (Kernel Space)** — `xdp_filter.c` : inspecte chaque paquet dès son arrivée sur l'interface, consulte la BPF Map `blacklist` (DROP immédiat si l'IP source y figure), et incrémente les compteurs par IP dans `ip_stats`.
- **Espace utilisateur (User Space)** — `ai_engine.py` : lit `ip_stats` périodiquement, calcule le débit (paquets/seconde) par IP, entraîne un modèle `IsolationForest` (scikit-learn), et inscrit les IP anormales dans `blacklist`.

## 3. Structure du dépôt

```
lab/
  topology.clab.yaml     Topologie Containerlab (4 conteneurs : attacker,
                          legit-client, xdp-router, target-server)
src/
  xdp_filter.c            Programme XDP/eBPF (style BCC), compilé et attaché
                          dynamiquement par ai_engine.py
  ai_engine.py             Moteur de détection d'anomalies (Isolation Forest)
                          + gestion des BPF Maps via bcc
scripts/
  run_benchmark.sh        Génère trafic légitime (iperf3) + attaque (hping3),
                          mesure CPU et latence, en mode baseline ou protected
  plot_benchmark.py       Génère les graphiques comparatifs (CPU, latence,
                          paquets acceptés/rejetés) à partir des résultats
  start_protection.sh     Lance ai_engine.py en arrière-plan avec logs + CSV
  stop_protection.sh      Arrête proprement ai_engine.py (détache le XDP)
tests/
  test_ai_engine_logic.py Tests unitaires (pytest) de la logique pure :
                          conversion IP, calcul pps, détection d'anomalies
                          -- ne nécessitent PAS bcc/eBPF (module mocké)
requirements.txt          Dépendances Python (scikit-learn, numpy, pandas,
                          matplotlib, pytest)
```

## 4. Prérequis

- Machine Linux (kernel 5.15+), Ubuntu 22.04/24.04 recommandé
- [Docker](https://docs.docker.com/engine/install/)
- [Containerlab](https://containerlab.dev/install/)
- Accès root (nécessaire pour attacher un programme XDP)

> ⚠️ **bcc et les headers noyau** : `ai_engine.py` compile `xdp_filter.c` à l'exécution via `bcc`, qui a besoin des headers du noyau de la machine **hôte** (les conteneurs partagent ce noyau). Si l'installation de `linux-headers-$(uname -r)` échoue dans le conteneur `xdp-router`, monter `/usr/src` et `/lib/modules` de l'hôte en bind read-only dans `lab/topology.clab.yaml`.

## 5. Installation et déploiement du lab

```bash
git clone https://github.com/Fabio1434/mems.git
cd mems

# Déployer la topologie (installe automatiquement bcc, scikit-learn, etc.
# dans le conteneur xdp-router au démarrage)
sudo containerlab deploy -t lab/topology.clab.yaml

# Vérifier la connectivité de bout en bout
sudo docker exec -it clab-xdp-ai-lab-attacker ping -c 3 10.0.3.2
```

## 6. Lancer la protection (XDP + IA)

Depuis le conteneur `xdp-router` :

```bash
sudo docker exec -it clab-xdp-ai-lab-xdp-router bash
python3 /root/ai_engine.py --iface eth1
```

Le script attache le programme XDP sur `eth1` (interface côté attaquant), puis boucle en continu : lecture des stats, entraînement/inférence du modèle, mise à jour de la blacklist.

**Options utiles :**

| Option | Rôle |
|---|---|
| `--iface <if>` | Interface où attacher le programme XDP (obligatoire) |
| `--ttl <sec>` | Durée avant déblocage automatique d'une IP (défaut : 60s) |
| `--log-csv <fichier>` | Log détaillé (timestamp, IP, pps, statut blacklist) pour un benchmark précis |

Ou via les scripts pratiques (gèrent le PID, les logs et le CSV automatiquement) :

```bash
./scripts/start_protection.sh eth1
./scripts/stop_protection.sh
```

Pour détacher manuellement le programme XDP en cas de besoin :

```bash
ip link set dev eth1 xdp off
```

> **Note sur la blacklist** : une IP blacklistée est automatiquement débloquée après expiration d'un TTL (60s par défaut, configurable via `--ttl`). Cela évite qu'un faux positif de l'IA ne bloque définitivement un client légitime.

## 7. Tests unitaires

La logique métier (conversion IP, calcul du débit, détection d'anomalies) est testable **sans bcc/eBPF** (donc sans machine Linux privilégiée), via un mock du module `bcc` :

```bash
pip3 install -r requirements.txt
pytest tests/test_ai_engine_logic.py -v
```

> **Limitation connue** : avec le paramètre `contamination` par défaut (0.05), le modèle Isolation Forest peut occasionnellement flaguer une IP légitime en même temps qu'un flood massif, si son débit s'écarte un peu de la distribution d'entraînement. Ce paramètre est à calibrer sur un jeu de trafic réel représentatif avant la démonstration finale -- c'est un point à documenter dans le rapport (compromis faux positifs / faux négatifs).

## 8. Lancer les benchmarks

```bash
cd scripts/

# Scénario 1 : sans protection (référence)
./run_benchmark.sh baseline

# Scénario 2 : avec XDP + IA actif
./run_benchmark.sh protected

# Générer les graphiques comparatifs
python3 plot_benchmark.py
```

Résultats produits dans `scripts/benchmark_results/` :
- `baseline/` et `protected/` — CSV bruts (CPU, latence, résumé de trafic)
- `graphs/` — `cpu_comparison.png`, `latency_comparison.png`, `packets_comparison.png`

## 9. Outils de génération de trafic et d'analyse

| Outil | Usage |
|---|---|
| `hping3` | Génération d'attaques DoS/DDoS (SYN/UDP flood) |
| `iperf3` | Génération de trafic légitime (bande passante) |
| `scapy` / `nmap` | Génération de paquets personnalisés / scans de ports |
| `bpftool` | Inspection des BPF Maps et programmes chargés |
| `tcpdump` | Capture de paquets pour validation |
| `htop` / `perf` | Analyse de charge CPU du routeur |

## 10. Livrables du mémoire

- [x] `xdp_filter.c` — programme noyau eBPF/XDP
- [x] `ai_engine.py` — moteur de détection IA + gestion des BPF Maps (avec TTL et logging CSV)
- [x] `topology.clab.yaml` — infrastructure de test
- [x] Tests unitaires de la logique de détection
- [ ] Dossier d'évaluation des performances (graphiques comparatifs) — à générer après exécution des benchmarks sur le lab réel
- [ ] Rapport de mémoire complet (état de l'art, conception, implémentation, résultats)
- [ ] Démonstration en direct devant le jury

## 11. Auteur

Fabio — Master 2 Télécommunications & Cybersécurité
