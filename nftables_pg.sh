#!/bin/bash
# ===================================================================
#  nftables-full-pg17-deb13-nossh-PROD.sh  (SIN ERRORES)
# ===================================================================
set -euo pipefail

PG_PORT=5432
PGB_PORT=6432
MON_PORT=9090
TRUSTED_NET_IPV4="192.168.143.0/24"
TRUSTED_NET_IPV6=""   # cámbialo o déjalo vacío si no usas IPv6
NFT_FILE="/etc/nftables.conf"
BACKUP_DIR="/root/nftables_backup_$(date +%Y%m%d_%H%M%S)"

log()  { echo "[$(date '+%F %T')] $*"; }
abort(){ log "ERROR: $*"; exit 1; }

[[ $EUID -eq 0 ]] || abort "Ejecutar como root"
command -v nft >/dev/null || { apt-get update -qq && apt-get install -y nftables fail2ban rsyslog; }

mkdir -p "$BACKUP_DIR"
cp -f "$NFT_FILE" "$BACKUP_DIR" 2>/dev/null || true

# ------------------------------------------------------------------------------
#  REGLAS NFTABLES  (SIN inet_addr, SIN SSH)
# ------------------------------------------------------------------------------
cat > "$NFT_FILE" <<'EOF'
#!/usr/sbin/nft -f
flush ruleset

define PG_PORT  = 5432
define PGB_PORT = 6432
define MON_PORT = 9090

table inet filter {
    set trusted_ipv4 {
        type ipv4_addr; flags interval;
        elements = { 127.0.0.1, 192.168.143.0/24 }
    }
    set trusted_ipv6 {
        type ipv6_addr; flags interval;
        elements = { ::1, fd00::/64 }
    }

    chain input {
        type filter hook input priority 0; policy drop;

        ct state established,related accept
        iif "lo" accept

        # ICMP
        ip protocol icmp icmp type echo-request limit rate 20/second burst 40 accept
        ip6 nexthdr ipv6-icmp accept

        # PostgreSQL  (solo localhost)
        tcp dport $PG_PORT ip saddr 127.0.0.1 accept
        tcp dport $PG_PORT ip6 saddr ::1   accept

        # PgBouncer  (red confiable)
        tcp dport $PGB_PORT ip saddr @trusted_ipv4 ct state new limit rate 300/second burst 500 accept
        tcp dport $PGB_PORT ip saddr @trusted_ipv4 accept
        tcp dport $PGB_PORT ip6 saddr @trusted_ipv6 ct state new limit rate 300/second burst 500 accept
        tcp dport $PGB_PORT ip6 saddr @trusted_ipv6 accept

        # Monitor (opcional, comentado)
        # tcp dport $MON_PORT ip saddr @trusted_ipv4 accept
        # tcp dport $MON_PORT ip6 saddr @trusted_ipv6 accept

        # Anti-port-scan
        tcp flags syn ct state new limit rate 100/second burst 200 accept
        tcp flags syn ct state new drop

        # Logging limitado
        tcp dport $PG_PORT log prefix "PG-BLOCK " limit rate 5/minute drop
        tcp dport $PGB_PORT log prefix "PGB-BLOCK " limit rate 5/minute drop
    }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain output  { type filter hook output  priority 0; policy accept; }
}
EOF

nft -c -f "$NFT_FILE" || abort "Sintaxis nftables inválida"
nft -f "$NFT_FILE"
systemctl enable --now nftables

# ------------------------------------------------------------------------------
# FAIL2BAN / RSYSLOG / MONITOR  (igual que antes, resumido)
# ------------------------------------------------------------------------------
mkdir -p /var/log/nftables
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = systemd
banaction = nftables-multiport

[postgresql]
enabled = true
port    = $PG_PORT,$PGB_PORT
filter  = postgresql
logpath = /var/log/postgresql/postgresql-*.log
bantime = 86400

[pgbouncer]
enabled = true
port    = $PGB_PORT
filter  = pgbouncer
logpath = /var/log/postgresql/pgbouncer.log
EOF
systemctl enable --now fail2ban

cat > /etc/rsyslog.d/30-nftables.conf <<EOF
if \$msg contains 'PG-BLOCK' or \$msg contains 'PGB-BLOCK' then /var/log/nftables/nftables.log
& stop
EOF
systemctl restart rsyslog

# Monitor rápido
MONITOR="/usr/local/bin/nft_mon.sh"
cat > "$MONITOR" <<'EOF'
#!/bin/bash
echo "=== $(date) ==="
echo "nftables: $(systemctl is-active nftables)  fail2ban: $(systemctl is-active fail2ban)"
echo "Conexiones PostgreSQL:"
sudo -u postgres psql -t -c "SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid();" 2>/dev/null || echo "0"
echo "Bloqueos recientes:"
tail -5 /var/log/nftables/nftables.log 2>/dev/null || echo "-"
EOF
chmod +x "$MONITOR"

log "Configuración finalizada. Backups en: $BACKUP_DIR"
echo "Comandos:  nft list ruleset  |  $MONITOR"
