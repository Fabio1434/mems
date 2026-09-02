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
                    │   │  (packets, bytes, syn_count) │
  [legit-client] ─eth2─┤ eth2                        │
                    │   eth3 ──────────────────────┼──eth1── [target-server]
                    └─────────────────────────────┘
```

- **Espace noyau (Kernel Space)** — `xdp_filter.c` : inspecte chaque paquet dès son arrivée sur l'interface, consulte la BPF Map `blacklist` (DROP immédiat si l'IP source y figure), et met à jour des statistiques **multi-critères** par IP dans `ip_stats` (nombre de paquets, octets totaux, paquets SYN-sans-ACK).
- **Espace utilisateur (User Space)** — `ai_engine.py` : lit `ip_stats` périodiquement, dérive 3 features par IP (débit, ratio de SYN, taille moyenne de paquet), entraîne un modèle `IsolationForest` multi-dimensionnel, calcule l'entropie de Shannon de la répartition du trafic entre IP sources, et inscrit les IP anormales dans `blacklist` (avec expiration automatique après un TTL configurable).

## 3. Détection multi-critères : ce qui rend le système robuste

Une détection basée sur le seul débit (paquets/seconde) manque deux catégories d'attaques réalistes. Ce projet y répond par deux mécanismes complémentaires :

**a) Détection multi-dimensionnelle par IP (`ai_engine.py::TrafficAnomalyDetector`)**

Le modèle Isolation Forest est entraîné sur 3 features simultanément :
- `pps` — débit brut
- `syn_ratio` — proportion de paquets SYN-sans-ACK (signature de SYN flood)
- `avg_pkt_size` — taille moyenne des paquets

Une IP au débit quasi-normal mais au `syn_ratio` très élevé (SYN flood "furtif", conçu pour rester sous un seuil de débit classique) est tout de même détectée — voir `tests/test_ai_engine_logic.py::test_detector_flags_stealthy_syn_flood_via_syn_ratio`.

Chaque blocage est journalisé avec la feature la plus atypique par rapport à la moyenne du trafic normal (`TrafficAnomalyDetector.explain()`), ce qui donne une **justification exploitable en soutenance** ("pourquoi cette IP a-t-elle été bloquée ?").

**b) Détection d'attaques distribuées par entropie des IP sources (`ai_engine.py::EntropyMonitor`)**

Un botnet qui répartit une attaque sur des milliers d'IP, chacune sous le seuil de détection individuel, échappe à la détection par IP. Le système calcule à chaque cycle l'**entropie de Shannon** de la répartition du trafic entre sources :

- Entropie proche de 0 → trafic concentré sur peu d'IP (flood classique, déjà couvert par la détection par IP).
- **Hausse brusque de l'entropie** au-dessus de la moyenne mobile récente → le trafic se répartit soudain sur beaucoup plus de sources qu'à l'habitude, signature typique d'une attaque distribuée. Une alerte est journalisée (et disponible dans le CSV de métriques pour analyse a posteriori).

> Limitation actuelle assumée : l'alerte d'entropie est journalisée mais ne déclenche pas encore de blocage automatique (bloquer massivement des IP sur la seule base d'un signal agrégé serait risqué pour le trafic légitime). C'est un axe de travail futur explicite pour le rapport : coupler l'alerte d'entropie à un rate-limiting global temporaire plutôt qu'à des DROP individuels.

**c) Ré-entraînement périodique (concept drift)**

Un modèle entraîné une seule fois au démarrage ne s'adapte jamais à l'évolution naturelle du trafic (heures de pointe, nouveaux usages). `ai_engine.py` maintient un historique de features en **fenêtre glissante** par IP (`MAX_HISTORY_PER_IP = 600` échantillons, borné via `collections.deque`) et **ré-entraîne le modèle périodiquement** (`--retrain-interval`, 5 min par défaut) sur cette fenêtre récente plutôt que sur tout l'historique depuis le démarrage.

**d) Détection UDP flood**

En plus du `syn_ratio` (SYN flood), le système calcule un `udp_ratio` par IP (proportion de paquets UDP), directement en lien avec le vecteur d'attaque "SYN/UDP Flood" mentionné dans le cahier des charges initial. Un flood UDP à débit quasi-normal mais avec un `udp_ratio` très atypique est détecté par le modèle multi-dimensionnel (voir `tests/test_ai_engine_logic.py::test_detector_flags_stealthy_udp_flood_via_udp_ratio`).

**e) Dashboard web temps réel**

`ai_engine.py` embarque un serveur HTTP (`http.server`, aucune dépendance externe) exposant :
- `GET /` — le dashboard (`dashboard/index.html`) : trafic par IP, graphe d'entropie, blacklist en direct, flux d'alertes
- `GET /api/stats` — un snapshot JSON de l'état courant, rafraîchi côté client toutes les 1.5s

Accessible sur `http://<ip-du-routeur>:8080` (port configurable via `--dashboard-port`, désactivable via `--no-dashboard`). Pensé pour la **démonstration en direct** demandée dans le cahier des charges : l'attaque et son blocage sont visibles en temps réel, sans dépendre de la lecture de logs texte.

## 3. Structure du dépôt

```
lab/
  topology.clab.yaml     Topologie Containerlab (4 conteneurs : attacker,
                          legit-client, xdp-router, target-server)
src/
  xdp_filter.c            Programme XDP/eBPF (style BCC), compilé et attaché
                          dynamiquement par ai_engine.py -- stats TCP/UDP
  ai_engine.py             Moteur de détection (Isolation Forest multi-critères,
                          entropie des IP sources, fenêtre glissante +
                          ré-entraînement périodique, dashboard web intégré)
dashboard/
  index.html               Dashboard temps réel (HTML/JS autonome, Chart.js
                          via CDN), servi directement par ai_engine.py
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
| `--retrain-interval <sec>` | Intervalle de ré-entraînement périodique du modèle (défaut : 300s) |
| `--dashboard-port <port>` | Port du dashboard web temps réel (défaut : 8080) |
| `--no-dashboard` | Désactive le dashboard web |
| `--log-csv <fichier>` | Log détaillé (timestamp, IP, features, blacklist, entropie) pour un benchmark précis |

Une fois lancé, le dashboard temps réel est accessible sur `http://<ip-du-routeur>:8080` (ou l'IP publiée par Containerlab pour ce conteneur).

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

> **Note sur `TRAINING_WINDOW`** : fixé empiriquement à 150 échantillons (voir tests). Avec un historique d'entraînement trop court (testé à 30), l'Isolation Forest manque de données pour bien séparer les anomalies subtiles (SYN flood furtif à débit quasi-normal) -- un point à documenter dans le rapport si vous ajustez cette valeur.

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
