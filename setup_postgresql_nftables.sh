#!/bin/bash
# ==============================================================================
#  Script  : nftables-full-pg17-deb13-no-ssh.sh
#  Objetivo: Firewall + Fail2Ban para PostgreSQL 17 y PgBouncer
#  SO      : Debian 13
#  RAM     : 20 GB (alto tráfico)
#  NOTA    : SIN SSH
# ==============================================================================

set -euo pipefail

# ------------------------------------------------------------------------------
# 0. CONFIGURACIÓN
# ------------------------------------------------------------------------------
PG_PORT=5432
PGB_PORT=6432
MON_PORT=9090

TRUSTED_NET="192.168.1.0/24"     # Red de aplicaciones
ADMIN_NET="192.168.1.0/24"       # Red administrativa (API / monitoreo)

NFT_FILE="/etc/nftables.conf"
BACKUP_DIR="/root/nftables_backup_$(date +%Y%m%d_%H%M%S)"

# ------------------------------------------------------------------------------
# 1. FUNCIONES
# ------------------------------------------------------------------------------
log()  { echo "[$(date '+%F %T')] $*"; }
abort(){ log "ERROR: $*"; exit 1; }

check_root() {
    [[ $EUID -eq 0 ]] || abort "Ejecutar como root"
}

install_pkg() {
    apt-get -qq update
    apt-get -qq install -y nftables fail2ban rsyslog iproute2 curl
}

# ------------------------------------------------------------------------------
# 2. PRE-CHEQUEOS
# ------------------------------------------------------------------------------
check_root
command -v nft >/dev/null || install_pkg

# ------------------------------------------------------------------------------
# 3. BACKUP
# ------------------------------------------------------------------------------
mkdir -p "$BACKUP_DIR"
cp -f "$NFT_FILE" "$BACKUP_DIR" 2>/dev/null || true
nft list ruleset > "$BACKUP_DIR/ruleset.old" 2>/dev/null || true
cp -f /etc/fail2ban/jail.local "$BACKUP_DIR" 2>/dev/null || true
log "Backups guardados en $BACKUP_DIR"

# ------------------------------------------------------------------------------
# 4. LOGS
# ------------------------------------------------------------------------------
mkdir -p /var/log/nftables /var/log/postgresql
chown postgres:adm /var/log/postgresql || true

# ------------------------------------------------------------------------------
# 5. NFTABLES (CARGA ATÓMICA)
# ------------------------------------------------------------------------------
TMP_NFT=$(mktemp)

cat > "$TMP_NFT" <<EOF
#!/usr/sbin/nft -f
flush ruleset

define PG_PORT=$PG_PORT
define PGB_PORT=$PGB_PORT
define MON_PORT=$MON_PORT

table inet filter {

    set trusted_ips {
        type inet_addr; flags interval;
        elements = { 127.0.0.1, ::1, $TRUSTED_NET }
    }

    set admin_ips {
        type inet_addr; flags interval;
        elements = { 127.0.0.1, ::1, $ADMIN_NET }
    }

    chain input {
        type filter hook input priority 0; policy drop;

        # Loopback
        iif lo accept

        # Estados
        ct state established,related accept
        tcp flags rst accept

        # ICMP limitado
        ip protocol icmp icmp type echo-request limit rate 10/second burst 20 accept
        ip6 nexthdr ipv6-icmp accept

        # PostgreSQL SOLO localhost
        tcp dport \$PG_PORT ip saddr {127.0.0.1, ::1} accept

        # PgBouncer (alto tráfico permitido)
        tcp dport \$PGB_PORT ip saddr @trusted_ips ct state new \
            limit rate 300/second burst 500 accept
        tcp dport \$PGB_PORT ip saddr @trusted_ips accept

        # Monitor opcional
        # tcp dport \$MON_PORT ip saddr @admin_ips accept

        # SYN flood protection
        tcp flags syn ct state new limit rate 100/second burst 200 accept
        tcp flags syn ct state new drop

        # Logging limitado
        tcp dport \$PG_PORT log prefix "PG-BLOCK " limit rate 5/minute drop
        tcp dport \$PGB_PORT log prefix "PGB-BLOCK " limit rate 5/minute drop
    }

    chain forward { type filter hook forward priority 0; policy drop; }
    chain output  { type filter hook output  priority 0; policy accept; }
}
EOF

nft -c -f "$TMP_NFT" || abort "Error de sintaxis nftables"
nft -f "$TMP_NFT"
mv "$TMP_NFT" "$NFT_FILE"

systemctl enable --now nftables
log "nftables activo"

# ------------------------------------------------------------------------------
# 6. FAIL2BAN (NFTABLES BACKEND)
# ------------------------------------------------------------------------------
cat > /etc/fail2ban/filter.d/postgresql.conf <<'EOF'
[Definition]
failregex = ^.*FATAL:.*password authentication failed.*host=<HOST>.*
            ^.*no pg_hba.conf entry.*host=<HOST>.*
EOF

cat > /etc/fail2ban/filter.d/pgbouncer.conf <<'EOF'
[Definition]
failregex = ^.*login failed.*from <HOST>.*
            ^.*auth failed.*<HOST>.*
EOF

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
backend   = systemd
banaction = nftables-multiport
bantime   = 86400
findtime  = 600
maxretry  = 3

[postgresql]
enabled  = true
filter   = postgresql
port     = $PG_PORT
journalmatch = _SYSTEMD_UNIT=postgresql.service

[pgbouncer]
enabled  = true
filter   = pgbouncer
port     = $PGB_PORT
logpath  = /var/log/postgresql/pgbouncer.log
EOF

systemctl enable --now fail2ban
log "Fail2Ban activo con backend nftables"

# ------------------------------------------------------------------------------
# 7. RSYSLOG
# ------------------------------------------------------------------------------
cat > /etc/rsyslog.d/30-nftables.conf <<EOF
if \$msg contains 'PG-BLOCK' or \$msg contains 'PGB-BLOCK' then /var/log/nftables/nftables.log
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
log "Logging configurado"

# ------------------------------------------------------------------------------
# 8. VERIFICACIÓN
# ------------------------------------------------------------------------------
log "Servicios:"
systemctl is-active nftables fail2ban

log "Prueba PostgreSQL local:"
sudo -u postgres pg_isready -p $PG_PORT

log "Prueba PgBouncer:"
sudo -u postgres pg_isready -h 127.0.0.1 -p $PGB_PORT || true

# ------------------------------------------------------------------------------
# 9. MONITOR
# ------------------------------------------------------------------------------
MONITOR="/usr/local/bin/nft_pg_mon.sh"
cat > "$MONITOR" <<'EOF'
#!/bin/bash
echo "=== $(date) ==="
echo "Servicios: nftables=$(systemctl is-active nftables) fail2ban=$(systemctl is-active fail2ban)"
echo "Conexiones activas PostgreSQL:"
sudo -u postgres psql -t -c "SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid();" 2>/dev/null
echo "Baneos PostgreSQL:"
fail2ban-client status postgresql 2>/dev/null | grep -i banned || echo "-"
echo "Últimos bloqueos:"
tail -5 /var/log/nftables/nftables.log 2>/dev/null || echo "-"
EOF
chmod +x "$MONITOR"

# ------------------------------------------------------------------------------
# 10. FIN
# ------------------------------------------------------------------------------
log "Configuración finalizada correctamente"
log "Backups en: $BACKUP_DIR"
echo
echo "Comandos útiles:"
echo "  Reglas nftables : nft list ruleset"
echo "  Monitor         : $MONITOR"
echo
exit 0
