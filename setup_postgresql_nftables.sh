#!/bin/bash
# ==============================================================================
# Script  : nftables-full-pg17-deb13.sh
# Objetivo: Seguridad PostgreSQL 17 + PgBouncer con nftables + fail2ban
# SO      : Debian 13
# Notas   : SIN SSH
# ==============================================================================

set -euo pipefail

################################################################################
# CONFIGURACIÓN
################################################################################
PG_PORT=5432
PGB_PORT=6432

TRUSTED_IPV4="192.168.143.0/24"
TRUSTED_IPV6="fd00::/64"

BACKUP_DIR="/root/nftables_backup_$(date +%Y%m%d_%H%M%S)"
NFT_FILE="/etc/nftables.conf"

################################################################################
# FUNCIONES
################################################################################
log()  { echo "[$(date '+%F %T')] $*"; }
abort(){ log "ERROR: $*"; exit 1; }

check_root() {
    [[ $EUID -eq 0 ]] || abort "Ejecutar como root"
}

install_pkgs() {
    apt-get -qq update
    apt-get -qq install -y nftables fail2ban rsyslog iproute2
}

validate_nft() {
    nft -c -f "$NFT_FILE" || abort "Error de sintaxis nftables"
}

################################################################################
# PRE-CHEQUEOS
################################################################################
check_root
command -v nft >/dev/null || install_pkgs

################################################################################
# BACKUP
################################################################################
mkdir -p "$BACKUP_DIR"
nft list ruleset > "$BACKUP_DIR/ruleset.old" 2>/dev/null || true
cp -f "$NFT_FILE" "$BACKUP_DIR" 2>/dev/null || true
cp -f /etc/fail2ban/jail.local "$BACKUP_DIR" 2>/dev/null || true
log "Backups guardados en $BACKUP_DIR"

################################################################################
# LOGS
################################################################################
mkdir -p /var/log/nftables /var/log/postgresql
chown postgres:adm /var/log/postgresql || true

################################################################################
# NFTABLES
################################################################################
cat > "$NFT_FILE" <<EOF
#!/usr/sbin/nft -f
flush ruleset

define PG_PORT=$PG_PORT
define PGB_PORT=$PGB_PORT

table inet filter {

    set trusted_ipv4 {
        type ipv4_addr;
        flags interval;
        elements = { 127.0.0.1, $TRUSTED_IPV4 }
    }

    set trusted_ipv6 {
        type ipv6_addr;
        flags interval;
        elements = { ::1, $TRUSTED_IPV6 }
    }

    chain input {
        type filter hook input priority 0; policy drop;

        iif lo accept

        ct state established,related accept
        tcp flags rst accept

        # ICMPv4
        ip protocol icmp accept limit rate 20/second burst 40

        # ICMPv6 (necesario)
        ip6 nexthdr ipv6-icmp icmpv6 type {
            echo-request, echo-reply,
            destination-unreachable, packet-too-big,
            time-exceeded, parameter-problem,
            nd-neighbor-solicit, nd-neighbor-advert,
            nd-router-solicit, nd-router-advert
        } accept limit rate 20/second burst 40

        # PostgreSQL SOLO localhost
        tcp dport \$PG_PORT ip  saddr 127.0.0.1 accept
        tcp dport \$PG_PORT ip6 saddr ::1 accept

        # PgBouncer redes confiables
        tcp dport \$PGB_PORT ip  saddr @trusted_ipv4 ct state new \
            accept limit rate 300/second burst 500
        tcp dport \$PGB_PORT ip6 saddr @trusted_ipv6 ct state new \
            accept limit rate 300/second burst 500

        tcp dport \$PGB_PORT ip  saddr @trusted_ipv4 accept
        tcp dport \$PGB_PORT ip6 saddr @trusted_ipv6 accept

        # Protección SYN flood
        tcp flags syn ct state new accept limit rate 100/second burst 200
        tcp flags syn ct state new drop

        # Logs controlados
        tcp dport \$PG_PORT  counter log prefix "PG-BLOCK "  limit rate 1/minute drop
        tcp dport \$PGB_PORT counter log prefix "PGB-BLOCK " limit rate 5/minute drop
    }

    chain forward { type filter hook forward priority 0; policy drop; }
    chain output  { type filter hook output  priority 0; policy accept; }
}

table inet f2b {

    set postgresql-ban {
        type ipv4_addr;
        flags dynamic, timeout;
        timeout 86400;
    }

    set pgbouncer-ban {
        type ipv4_addr;
        flags dynamic, timeout;
        timeout 7200;
    }

    chain input {
        type filter hook input priority -5;
        ip saddr @postgresql-ban drop
        ip saddr @pgbouncer-ban drop
    }
}
EOF

validate_nft
nft -f "$NFT_FILE"
systemctl enable --now nftables
log "nftables aplicado correctamente"

################################################################################
# FAIL2BAN
################################################################################
cat > /etc/fail2ban/filter.d/postgresql.conf <<'EOF'
[Definition]
failregex = .*password authentication failed.*
            .*no pg_hba.conf entry.*
EOF

cat > /etc/fail2ban/filter.d/pgbouncer.conf <<'EOF'
[Definition]
failregex = .*login failed.*
            .*auth failed.*
EOF

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = auto

[postgresql]
enabled  = true
port     = $PG_PORT
filter   = postgresql
logpath  = /var/log/postgresql/postgresql-*.log
bantime  = 86400

[pgbouncer]
enabled  = true
port     = $PGB_PORT
filter   = pgbouncer
logpath  = /var/log/postgresql/pgbouncer.log
bantime  = 7200
EOF

systemctl enable --now fail2ban
log "Fail2ban activo"

################################################################################
# RSYSLOG + ROTATE
################################################################################
cat > /etc/rsyslog.d/30-nftables.conf <<EOF
if \$programname == 'kernel' and \$msg contains 'BLOCK' then /var/log/nftables/nftables.log
& stop
EOF

cat > /etc/logrotate.d/nftables <<EOF
/var/log/nftables/nftables.log {
    daily
    rotate 30
    compress
    missingok
    notifempty
    create 640 root adm
    postrotate
        systemctl kill -s HUP rsyslog.service
    endscript
}
EOF

systemctl restart rsyslog
log "Logs configurados"

################################################################################
# VERIFICACIÓN
################################################################################
log "Estado servicios:"
systemctl is-active nftables fail2ban

log "Prueba PostgreSQL:"
sudo -u postgres pg_isready -p $PG_PORT

log "Prueba PgBouncer:"
sudo -u postgres pg_isready -h 127.0.0.1 -p $PGB_PORT || true

################################################################################
# FIN
################################################################################
log "CONFIGURACIÓN COMPLETA Y ESTABLE"
log "Backup en: $BACKUP_DIR"

echo
echo "Comandos útiles:"
echo "  nft list ruleset"
echo "  fail2ban-client status"
echo
exit 0
