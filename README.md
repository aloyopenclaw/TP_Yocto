# TP Yocto — Image Linux Durcie pour une Gateway IoT

**Master 2 ESGI — IoT Avancée avec Yocto Project**
**Aloy**

## Ce qu'on a fait

On part de `core-image-base` et on construit une image Linux durcie pour
une passerelle IoT. Cinq axes de durcissement :

1. **Comptes** : `root` verrouillé, un compte `admin` dédié avec sudo.
2. **SSH** : `PermitRootLogin no`, authentification par mot de passe
   uniquement, pas de clé publique.
3. **Rootfs immuable** : `read-only-rootfs` — impossible d'écrire sur `/`.
4. **Flags de compilation** : `security_flags.inc` (déjà actif par défaut
   dans Poky — stack protector, FORTIFY_SOURCE, RELRO/NOW, PIE).
5. **Pare-feu** : `iptables` en mode *default deny*, seul SSH (port 22) et
   `lo` sont autorisés.

L'image a également été passée au crible de `cve-check` : 21 166 CVE
analysées, dont deux Critical (curl 9.8 et noyau Linux 9.8) sont analysées
en détail dans le rapport.

## Structure du repo

```
TP_Yocto/
├── README.md                          ← vous êtes ici
├── rapport-audit.pdf                  ← le rapport complet
├── rapport-audit.md                   ← version Markdown
├── screenshots/                       ← captures QEMU (preuves)
│   ├── 01_build_complete.png
│   ├── 02_rootfs_readonly.png
│   ├── 03_ssh_root_denied.png
│   ├── 04_iptables_rules.png
│   ├── 05_sshd_config.png
│   └── 06_cve_report.png
└── meta-iot-gateway-hardened/         ← le layer à intégrer
    ├── conf/layer.conf
    ├── recipes-core/images/
    │   └── iot-gateway-image.bb       ← la recette d'image
    ├── recipes-connectivity/openssh/
    │   ├── openssh_%.bbappend         ← injection du sshd_config
    │   └── files/sshd_config          ← config SSH durcie
    └── recipes-filter/firewall-config/
        ├── firewall-config_1.0.bb     ← recette du pare-feu
        └── files/firewall-init        ← script init iptables
```

## Comment intégrer le layer

### Pré-requis

- Un build Yocto fonctionnel (branche `scarthgap`), avec `poky` cloné.
- Les layers `meta-openembedded` (pour `htop`, `tcpdump` si vous en avez
  besoin) et idéalement `meta-security` même si on ne l'utilise pas
  directement pour les recettes — il apporte des outils complémentaires.

### Étape 1 — Cloner le layer

Placez le répertoire `meta-iot-gateway-hardened` au même niveau que
`poky` (ou à l'intérieur, les deux fonctionnent) :

```bash
cd /path/to/poky
cp -r meta-iot-gateway-hardened .
```

### Étape 2 — Cloner `meta-security`

```bash
git clone -b scarthgap https://git.yoctoproject.org/meta-security
```

### Étape 3 — Activer les layers dans `bblayers.conf`

Dans `build/conf/bblayers.conf`, ajoutez :

```bitbake
BBLAYERS += " \
  /path/to/poky/meta-iot-gateway-hardened \
  /path/to/meta-security \
"
```

Ou plus simple, depuis votre environnement de build :

```bash
cd /path/to/poky
source oe-init-build-env
bitbake-layers add-layer ../meta-iot-gateway-hardened
bitbake-layers add-layer ../meta-security
```

### Étape 4 — Configurer `local.conf`

Ajoutez à la fin de `build/conf/local.conf` :

```bitbake
# Désactiver debug-tweaks — sinon ssh_allow_root_login() force
# PermitRootLogin yes et casse notre durcissement SSH
EXTRA_IMAGE_FEATURES = ""

# Machine cible
MACHINE = "qemux86-64"

# Activer cve-check
INHERIT += "cve-check"
```

### Étape 5 — Builder

```bash
bitbake iot-gateway-image
```

### Étape 6 — Tester dans QEMU

```bash
runqemu qemux86-64 nographic slirp kvm
```

Login : `admin` / Mot de passe : `AdminTP2026!`

## Recettes — ce que chaque fichier fait

### `iot-gateway-image.bb`

La recette principale. Elle hérite de `core-image` (via `core-image-base`)
et de `extrausers`. C'est là que tout se joue :

| Directive | Rôle |
|-----------|------|
| `IMAGE_FEATURES += "ssh-server-openssh read-only-rootfs"` | Active SSH + rootfs en lecture seule |
| `IMAGE_INSTALL:append = " iptables sudo firewall-config"` | Installe les paquets nécessaires |
| `EXTRA_USERS_PARAMS` | Crée le compte `admin`, verrouille `root` |
| `setup_sudoers()` | Ajoute `%sudo ALL=(ALL) ALL` dans sudoers |

### `openssh_%.bbappend` + `files/sshd_config`

Le bbappend injecte notre `sshd_config` personnalisé dans le paquet
OpenSSH au moment du `do_install`. Trois directives :

```
PermitRootLogin no
PasswordAuthentication yes
PubkeyAuthentication no
```

### `firewall-config_1.0.bb` + `files/firewall-init`

Installe un script SysV init (`/etc/init.d/firewall`) qui s'exécute au
boot via `update-rc.d`. Le script :

- charge les modules noyau `iptable_filter`, `xt_tcpudp`, `nf_conntrack`
- met les politiques INPUT et FORWARD à `DROP`
- autorise `lo` et le port 22 (SSH)

## Captures d'écran

Toutes les captures sont dans `screenshots/`. Elles proviennent de
l'exécution réelle de l'image dans QEMU sur notre VPS de build (Debian 12,
KVM). Le VPS étant headless, les captures sont des relevés de la console
série rendus en image.

| Capture | Ce qu'elle prouve |
|---------|-------------------|
| `01_build_complete.png` | Le build termine avec `BITBAKE_EXIT=0` (2h 2min) |
| `02_rootfs_readonly.png` | `touch /forbidden_test` → "Read-only file system" |
| `03_ssh_root_denied.png` | `ssh root@localhost` → "Permission denied" |
| `04_iptables_rules.png` | INPUT policy DROP, FORWARD DROP, OUTPUT ACCEPT |
| `05_sshd_config.png` | `PermitRootLogin no` confirmé en runtime |
| `06_cve_report.png` | Rapport CVE : 373 vulnérabilités High/Critical |

## Le compte `admin`

- **Login** : `admin`
- **Mot de passe** : `AdminTP2026!`
- Le hash SHA-512 est généré avec `openssl passwd -6` et hardcodé dans
  la recette (échappement `\$` pour BitBake).

## Pièges rencontrés (et résolus)

Trois choses qui nous ont fait perdre du temps et qui méritent d'être
documentées :

1. **`extrausers` ne fait pas de substitution shell**. On ne peut pas
   écrire `useradd -p '$(openssl passwd -6 ...)'` — il faut pré-générer
   le hash et l'échapper avec `\$`.

2. **`debug-tweaks` override `PermitRootLogin`**. Le template par défaut
   de `local.conf` met `EXTRA_IMAGE_FEATURES ?= "debug-tweaks"`, ce qui
   déclenche `ssh_allow_root_login()` qui force `PermitRootLogin yes`.
   Il faut le désactiver : `EXTRA_IMAGE_FEATURES = ""`.

3. **Les modules iptables ne sont pas chargés par défaut** dans le
   noyau `linux-yocto` de `qemux86-64`. On a ajouté des `modprobe` au
   début du script firewall. Les politiques DROP fonctionnent quand
   même, seules les règles d'exception (port 22, conntrack) nécessitent
   ces modules.

## Versions

- **poky** : branche `scarthgap` (commit `6b7474f7ca29076d28df81a49feec6311fa18202`)
- **meta-openembedded** : branche `scarthgap`
- **meta-security** : branche `scarthgap`
- **BitBake** : 2.8.1
- **Distro** : poky 5.0.19
