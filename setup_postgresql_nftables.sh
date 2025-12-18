#!/bin/bash
# ==============================================================================
# Script  : nftables-pg17-deb13-PROD-FINAL.sh
# Objetivo: Firewall + Fail2Ban para PostgreSQL 17 y PgBouncer
# SO      : Debian 13
# Perfil  : PRODUCCIÓN CRÍTICA / ALTO TRÁFICO
# Nota    : SIN SSH / Dual-stack / Carga atómica
# ==============================================================================

set -euo pipefail

################################################################################
# 0. CONFIGURACIÓN
################################################################################
PG_PORT=5432
PGB_PORT=6432
MON_PORT=9090

TRUSTED_NET_IPV4="192.168.143.0/24"
TRUSTED_NET_IPV6="fd00::/64"   # Vacío si no usas IPv6

NFT_FILE="/etc/nftables.conf"
BACKUP_DIR="/root/nftables_backup_$(date +%Y%m%d_%H%M%S)"

################################################################################
# 1. FUNCIONES
################################################################################
log()   { echo "[$(date '+%F %T')] $*"; }
abort() { log "ERROR: $*"; exit 1; }

check_root() {
    [[ $EUID -eq 0 ]] || abort "Ejecutar como root"
}

install_pkg() {
    apt-get -qq update
    apt-get -qq install -y nftables fail2ban rsyslog
}

################################################################################
# 2. PRE-CHEQUEOS
################################################################################
check_root
command -v nft >/dev/null || install_pkg

################################################################################
# 3. BACKUP
################################################################################
mkdir -p "$BACKUP_DIR"
cp -f "$NFT_FILE" "$BACKUP_DIR" 2>/dev/null || true
nft list ruleset > "$BACKUP_DIR/ruleset.old" 2>/dev/null || true
cp -f /etc/fail2ban/jail.local "$BACKUP_DIR" 2>/dev/null || true
log "Backups guardados en $BACKUP_DIR"

################################################################################
# 4. LOGS
################################################################################
mkdir -p /var/log/nftables /var/log/postgresql
chown postgres:adm /var/log/postgresql || true

################################################################################
# 5. NFTABLES (CARGA ATÓMICA)
################################################################################
TMP_NFT=$(mktemp)

cat > "$TMP_NFT" <<EOF
#!/usr/sbin/nft -f
flush ruleset

define PG_PORT=$PG_PORT
define PGB_PORT=$PGB_PORT
define MON_PORT=$MON_PORT

table inet filter {

    set trusted_ipv4 {
        type ipv4_addr; flags interval;
        elements = { 127.0.0.1, $TRUSTED_NET_IPV4 }
    }

    set trusted_ipv6 {
        type ipv6_addr; flags interval;
        elements = { ::1, $TRUSTED_NET_IPV6 }
    }

    chain input {
        type filter hook input priority 0; policy drop;

        # Loopback
        iif lo accept

        # Estados
        ct state established,related accept
        tcp flags rst accept

        # ICMPv4 esencial
        ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable } \
            limit rate 20/second burst 40 accept
        ip protocol icmp accept

        # ICMPv6 esencial (ND incluido)
        ip6 nexthdr ipv6-icmp icmpv6 type {
            echo-request, echo-reply, destination-unreachable,
            packet-too-big, time-exceeded, parameter-problem,
            nd-neighbor-solicit, nd-neighbor-advert,
            nd-router-solicit, nd-router-advert
        } limit rate 20/second burst 40 accept

        # PostgreSQL SOLO localhost (defensivo)
        tcp dport \$PG_PORT ip  saddr 127.0.0.1 accept
        tcp dport \$PG_PORT ip6 saddr ::1 accept

        # PgBouncer desde redes confiables (alto tráfico)
        tcp dport \$PGB_PORT ip  saddr @trusted_ipv4 ct state new \
            limit rate 300/second burst 500 accept
        tcp dport \$PGB_PORT ip6 saddr @trusted_ipv6 ct state new \
            limit rate 300/second burst 500 accept
        tcp dport \$PGB_PORT ip  saddr @trusted_ipv4 accept
        tcp dport \$PGB_PORT ip6 saddr @trusted_ipv6 accept

        # Monitor opcional
        # tcp dport \$MON_PORT ip  saddr @trusted_ipv4 accept
        # tcp dport \$MON_PORT ip6 saddr @trusted_ipv6 accept

        # Protección SYN flood
        tcp flags syn ct state new limit rate 100/second burst 200 accept
        tcp flags syn ct state new drop

        # Logging defensivo (limitado)
        tcp dport \$PG_PORT counter log prefix "PG-BLOCK " limit rate 1/minute drop
        tcp dport \$PGB_PORT counter log prefix "PGB-BLOCK " limit rate 5/minute drop
    }

    chain forward { type filter hook forward priority 0; policy drop; }
    chain output  { type filter hook output  priority 0; policy accept; }
}

# Tabla exclusiva para Fail2Ban
table inet f2b {
    set postgresql-ban {
        type inet_addr; flags dynamic, timeout;
        timeout 86400
    }

    set pgbouncer-ban {
        type inet_addr; flags dynamic, timeout;
        timeout 7200
    }

    chain input {
        type filter hook input priority -5;
        ip saddr @postgresql-ban drop
        ip saddr @pgbouncer-ban drop
    }
}
EOF

nft -c -f "$TMP_NFT" || abort "Error de sintaxis nftables"
nft -f "$TMP_NFT"
mv "$TMP_NFT" "$NFT_FILE"

systemctl enable --now nftables
log "nftables aplicado correctamente (carga atómica)"

################################################################################
# 6. FAIL2BAN (NFTABLES REAL)
################################################################################
cat > /etc/fail2ban/filter.d/postgresql.conf <<'EOF'
[Definition]
failregex = ^%(__prefix_line)sFATAL:\s+password authentication failed for user ".*"$
            ^%(__prefix_line)sFATAL:\s+no pg_hba.conf entry for host ".*", user ".*".*$
            ^%(__prefix_line)sERROR:\s+authentication failed for user ".*"$
ignoreregex = ^%(__prefix_line)sLOG:\s+(connection authorized|connection closed)
EOF

cat > /etc/fail2ban/filter.d/pgbouncer.conf <<'EOF'
[Definition]
failregex = ^.*login failed:.*$
            ^.*auth failed:.*$
ignoreregex = ^.*(connection ok|new connection).*
EOF

cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
backend   = systemd
bantime   = 3600
findtime  = 600
maxretry  = 3

[postgresql]
enabled   = true
filter    = postgresql
port      = $PG_PORT
journalmatch = _SYSTEMD_UNIT=postgresql.service
action    = nftables-multiport[name=postgresql, port="$PG_PORT", table="f2b", setname="postgresql-ban"]
bantime   = 86400

[pgbouncer]
enabled   = true
filter    = pgbouncer
port      = $PGB_PORT
logpath   = /var/log/postgresql/pgbouncer.log
action    = nftables-multiport[name=pgbouncer, port="$PGB_PORT", table="f2b", setname="pgbouncer-ban"]
bantime   = 7200
EOF

systemctl enable --now fail2ban
fail2ban-client reload
log "Fail2Ban integrado correctamente con nftables"

################################################################################
# 7. LOGGING
################################################################################
cat > /etc/rsyslog.d/30-nftables.conf <<'EOF'
if ($msg contains 'PG-BLOCK' or $msg contains 'PGB-BLOCK') then {
    action(type="omfile" file="/var/log/nftables/nftables.log")
    stop
}
EOF

cat > /etc/logrotate.d/nftables <<'EOF'
/var/log/nftables/nftables.log
/var/log/postgresql/pgbouncer.log
{
    daily
    rotate 30
    compress
    delaycompress
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

################################################################################
# 8. VERIFICACIÓN
################################################################################
log "Servicios:"
systemctl is-active nftables fail2ban

log "PostgreSQL local:"
sudo -u postgres pg_isready -p $PG_PORT

log "PgBouncer local:"
sudo -u postgres pg_isready -h 127.0.0.1 -p $PGB_PORT || true

################################################################################
# 9. MONITOR
################################################################################
MONITOR="/usr/local/bin/nft_pg_monitor.sh"
cat > "$MONITOR" <<'EOF'
#!/bin/bash
echo "=== $(date '+%F %T') ==="
echo "Servicios:"
systemctl is-active nftables fail2ban
echo

echo "Conexiones PostgreSQL:"
sudo -u postgres psql -t -c "SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid();" 2>/dev/null
echo

echo "Fail2Ban:"
for jail in postgresql pgbouncer; do
    fail2ban-client status "$jail" 2>/dev/null | grep -E "Status|Currently banned"
done
echo

echo "NFTables bloqueos recientes:"
tail -5 /var/log/nftables/nftables.log 2>/dev/null || echo "-"
EOF

chmod +x "$MONITOR"

################################################################################
# 10. FIN
################################################################################
log "CONFIGURACIÓN FINALIZADA CORRECTAMENTE"
log "Backups en: $BACKUP_DIR"
echo
echo "Comandos útiles:"
echo "  Ver reglas : nft list ruleset"
echo "  Monitor    : $MONITOR"
echo
exit 0
