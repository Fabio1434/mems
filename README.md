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

Un modèle entraîné une seule fois au démarrage ne s'adapte jamais à l'évolution naturelle du trafic (heures de pointe, nouveaux usages). `ai_engine.py` maintient un historique de features en **fenêtre glissante** par IP (`max_history_per_ip`, borné via `collections.deque`) et **ré-entraîne le modèle périodiquement** (`--retrain-interval` ou `detection.retrain_interval_sec`, 5 min par défaut) sur cette fenêtre récente plutôt que sur tout l'historique depuis le démarrage.

**d) Détection UDP flood**

En plus du `syn_ratio` (SYN flood), le système calcule un `udp_ratio` par IP (proportion de paquets UDP), directement en lien avec le vecteur d'attaque "SYN/UDP Flood" mentionné dans le cahier des charges initial.

**e) Dashboard web temps réel**

`ai_engine.py` embarque un serveur HTTP (`http.server`, aucune dépendance externe) exposant :
- `GET /` — le dashboard (`dashboard/index.html`) : trafic par IP, graphe d'entropie, blacklist en direct, flux d'alertes
- `GET /api/stats` — un snapshot JSON de l'état courant, rafraîchi côté client toutes les 1.5s

Accessible sur `http://<ip-du-routeur>:8080` par défaut (voir section 8 pour la configuration de sécurité de l'accès).

## 4. Robustesse pour un déploiement réel (au-delà du lab de démonstration)

Un PoC de soutenance et un outil qu'on peut réellement tester sur un réseau ont des exigences différentes. Ces mécanismes comblent l'écart :

**a) Maps BPF en LRU (résistance à la saturation sous attaque réelle)**

`blacklist` et `ip_stats` utilisent le type `lru_hash` plutôt que `hash` standard. Sous une vraie attaque avec des IP source massivement usurpées, une table de taille fixe peut se remplir et rejeter silencieusement les nouvelles entrées. Le type LRU évince automatiquement les entrées les moins récemment utilisées -- le système continue de fonctionner sous forte charge plutôt que de "geler" silencieusement.

**b) Persistance du modèle entre redémarrages**

Sans persistance, chaque redémarrage repart de zéro : il faut réaccumuler `training_window` échantillons (150 par défaut, ~5 min à 2s/cycle) avant la première détection -- une fenêtre de vulnérabilité à chaque redémarrage. En renseignant `detection.model_path` dans la config, le modèle entraîné est sauvegardé (`joblib`) après chaque entraînement et rechargé automatiquement au démarrage : la détection est immédiatement active, même juste après un redémarrage.

**c) Sécurisation du dashboard**

Le dashboard expose des données de trafic réseau en temps réel -- sans protection, n'importe qui atteignant le port peut les consulter. Deux mécanismes indépendants :
- `dashboard.bind_host` : `"127.0.0.1"` par défaut (accessible uniquement depuis la machine elle-même). Mettre `"0.0.0.0"` explicitement seulement si un accès distant est nécessaire (ex: démonstration en salle).
- `dashboard.token` : si renseigné, chaque requête doit inclure `?token=...` dans l'URL, sinon `401 Unauthorized`. À utiliser systématiquement si `bind_host` n'est pas `"127.0.0.1"`.


## 5. Structure du dépôt

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
config/
  example.yaml             Modèle de fichier de configuration (à copier et
                          adapter par environnement testé -- interface,
                          whitelist, dry-run, seuils, sécurité dashboard)
models/
  (généré)                 Modèles entraînés sauvegardés (joblib), un par
                          environnement -- non versionné (voir .gitignore),
                          activé via detection.model_path dans la config
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

## 6. Prérequis

- Machine Linux (kernel 5.15+), Ubuntu 22.04/24.04 recommandé
- [Docker](https://docs.docker.com/engine/install/)
- [Containerlab](https://containerlab.dev/install/)
- Accès root (nécessaire pour attacher un programme XDP)

> ⚠️ **bcc et les headers noyau** : `ai_engine.py` compile `xdp_filter.c` à l'exécution via `bcc`, qui a besoin des headers du noyau de la machine **hôte** (les conteneurs partagent ce noyau). Si l'installation de `linux-headers-$(uname -r)` échoue dans le conteneur `xdp-router`, monter `/usr/src` et `/lib/modules` de l'hôte en bind read-only dans `lab/topology.clab.yaml`.

## 7. Installation et déploiement du lab

```bash
git clone https://github.com/Fabio1434/mems.git
cd mems

# Déployer la topologie (installe automatiquement bcc, scikit-learn, etc.
# dans le conteneur xdp-router au démarrage)
sudo containerlab deploy -t lab/topology.clab.yaml

# Vérifier la connectivité de bout en bout
sudo docker exec -it clab-xdp-ai-lab-attacker ping -c 3 10.0.3.2
```

## 8. Configuration par environnement (fichier config.yaml)

Pour tester ce système sur un réseau réel (pas seulement le lab de développement), **ne pas modifier le code** -- créer un fichier de configuration dédié à cet environnement :

```bash
cp config/example.yaml config/mon-environnement.yaml
# éditer mon-environnement.yaml : interface, whitelist, dry_run, seuils...
python3 src/ai_engine.py --config config/mon-environnement.yaml
```

Les arguments en ligne de commande (`--ttl`, `--iface`, etc.), s'ils sont fournis, ont priorité sur le fichier de configuration.

### Mode simulation (dry-run) -- à utiliser en premier sur tout nouveau réseau

```yaml
blacklist:
  dry_run: true
```

En mode dry-run, le système **détecte et journalise** les anomalies (visibles dans les logs, le dashboard, et le CSV si `--log-csv` est utilisé) mais **ne bloque jamais réellement de trafic**. C'est le point de départ recommandé pour tout nouvel environnement testé : faire tourner le système quelques heures/jours en dry-run, observer le taux de détection, ajuster `contamination` et les seuils, **avant** de passer en `dry_run: false`.

### Liste blanche (whitelist) -- filet de sécurité obligatoire

```yaml
blacklist:
  whitelist:
    - 10.0.2.1   # passerelle réseau
    - 8.8.8.8    # ex: résolveur DNS
```

Les IP de la whitelist ne sont **jamais** bloquées, même si le modèle les juge anormales. À renseigner systématiquement pour toute IP dont le blocage aurait un impact critique (passerelle, DNS, sondes de supervision, IP de management).

## 9. Lancer la protection (XDP + IA)

Depuis le conteneur `xdp-router` :

```bash
sudo docker exec -it clab-xdp-ai-lab-xdp-router bash

# Avec un fichier de config (recommandé)
python3 /root/ai_engine.py --config /root/config/mon-environnement.yaml

# Ou en ligne de commande directe
python3 /root/ai_engine.py --iface eth1
```

Le script attache le programme XDP sur `eth1` (interface côté attaquant), puis boucle en continu : lecture des stats, entraînement/inférence du modèle, mise à jour de la blacklist.

**Options utiles :**

| Option | Rôle |
|---|---|
| `--config <fichier>` | Fichier YAML de configuration (voir section 6) |
| `--iface <if>` | Interface où attacher le programme XDP (obligatoire si absent du fichier de config) |
| `--dry-run` | Force le mode simulation (détecte, ne bloque jamais) |
| `--model-path <fichier>` | Sauvegarde/charge le modèle entraîné entre redémarrages (joblib) |
| `--ttl <sec>` | Durée avant déblocage automatique d'une IP (défaut : 60s) |
| `--retrain-interval <sec>` | Intervalle de ré-entraînement périodique du modèle (défaut : 300s) |
| `--dashboard-port <port>` | Port du dashboard web temps réel (défaut : 8080) |
| `--no-dashboard` | Désactive le dashboard web |
| `--log-csv <fichier>` | Log détaillé (timestamp, IP, features, blacklist, entropie) pour un benchmark précis |

Une fois lancé, le dashboard temps réel est accessible sur `http://<ip-du-routeur>:8080` (ou l'IP publiée par Containerlab pour ce conteneur). En mode dry-run, un bandeau d'avertissement s'affiche en haut du dashboard.

Ou via les scripts pratiques (gèrent le PID, les logs et le CSV automatiquement) :

```bash
./scripts/start_protection.sh config/mon-environnement.yaml
# ou, sans fichier de config :
./scripts/start_protection.sh "" eth1

./scripts/stop_protection.sh
```

Pour détacher manuellement le programme XDP en cas de besoin :

```bash
ip link set dev eth1 xdp off
```

> **Note sur la blacklist** : une IP blacklistée est automatiquement débloquée après expiration d'un TTL (60s par défaut, configurable via `--ttl`). Cela évite qu'un faux positif de l'IA ne bloque définitivement un client légitime.

> **Note sur `TRAINING_WINDOW`** : fixé empiriquement à 150 échantillons (voir tests). Avec un historique d'entraînement trop court (testé à 30), l'Isolation Forest manque de données pour bien séparer les anomalies subtiles (SYN flood furtif à débit quasi-normal) -- un point à documenter dans le rapport si vous ajustez cette valeur.

## 10. Tests unitaires

La logique métier (conversion IP, calcul du débit, détection d'anomalies) est testable **sans bcc/eBPF** (donc sans machine Linux privilégiée), via un mock du module `bcc` :

```bash
pip3 install -r requirements.txt
pytest tests/test_ai_engine_logic.py -v
```

> **Limitation connue** : avec le paramètre `contamination` par défaut (0.05), le modèle Isolation Forest peut occasionnellement flaguer une IP légitime en même temps qu'un flood massif, si son débit s'écarte un peu de la distribution d'entraînement. Ce paramètre est à calibrer sur un jeu de trafic réel représentatif avant la démonstration finale -- c'est un point à documenter dans le rapport (compromis faux positifs / faux négatifs).

## 11. Lancer les benchmarks

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

## 12. Outils de génération de trafic et d'analyse

| Outil | Usage |
|---|---|
| `hping3` | Génération d'attaques DoS/DDoS (SYN/UDP flood) |
| `iperf3` | Génération de trafic légitime (bande passante) |
| `scapy` / `nmap` | Génération de paquets personnalisés / scans de ports |
| `bpftool` | Inspection des BPF Maps et programmes chargés |
| `tcpdump` | Capture de paquets pour validation |
| `htop` / `perf` | Analyse de charge CPU du routeur |

## 13. Livrables du mémoire

- [x] `xdp_filter.c` — programme noyau eBPF/XDP (TCP + UDP, maps LRU)
- [x] `ai_engine.py` — moteur de détection IA + gestion des BPF Maps (TTL, dashboard, config, dry-run, whitelist, persistance)
- [x] `topology.clab.yaml` — infrastructure de test
- [x] Tests unitaires de la logique de détection (40 tests)
- [x] Dashboard temps réel pour la démonstration en direct (sécurisé : bind restreint + token)
- [x] Fichier de configuration par environnement + mode simulation (dry-run) pour un déploiement sûr sur un réseau réel
- [x] Robustesse sous charge réelle (maps LRU) + persistance du modèle entre redémarrages
- [ ] Dossier d'évaluation des performances (graphiques comparatifs) — à générer après exécution des benchmarks sur le lab réel
- [ ] Rapport de mémoire complet (état de l'art, conception, implémentation, résultats)
- [ ] Démonstration en direct devant le jury

## 14. Auteur

Fabio — Master 2 Télécommunications & Cybersécurité
