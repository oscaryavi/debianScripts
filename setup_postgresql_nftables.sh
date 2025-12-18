#!/bin/bash
# ==============================================================================
#  nftables-full-pg17-deb13-no-ssh  (CORREGIDO)
# ==============================================================================
set -euo pipefail

PG_PORT=5432
PGB_PORT=6432
TRUSTED_NET="192.168.1.0/24"
NFT_FILE="/etc/nftables.conf"
BACKUP_DIR="/root/nftables_backup_$(date +%Y%m%d_%H%M%S)"

log()  { echo "[$(date '+%F %T')] $*"; }
abort(){ log "ERROR-OSCAR: $*"; exit 1; }

[[ $EUID -eq 0 ]] || abort "Ejecutar como root"
command -v nft >/dev/null || { apt-get update -qq && apt-get install -y nftables fail2ban rsyslog; }

mkdir -p "$BACKUP_DIR"
cp -f "$NFT_FILE" "$BACKUP_DIR" 2>/dev/null || true

# ------------------------------------------------------------------------------
#  REGULAS NFTABLES COMPATIBLES
# ------------------------------------------------------------------------------
cat > "$NFT_FILE" <<'EOF'
#!/usr/sbin/nft -f
flush ruleset

define PG_PORT  = 5432
define PGB_PORT = 6432

table inet filter {
    set trusted_ipv4 {
        type ipv4_addr; flags interval;
        elements = { 127.0.0.1, 192.168.1.0/24 }
    }
    set trusted_ipv6 {
        type ipv6_addr; flags interval;
        elements = { ::1 }
    }

    chain input {
        type filter hook input priority 0; policy drop;

        ct state established,related accept
        iif "lo" accept

        # ICMP
        ip protocol icmp icmp type echo-request limit rate 10/second burst 20 accept
        ip6 nexthdr ipv6-icmp accept

        # PostgreSQL solo localhost
        tcp dport $PG_PORT ip saddr 127.0.0.1 accept
        tcp dport $PG_PORT ip6 saddr ::1   accept

        # PgBouncer
        tcp dport $PGB_PORT ip  saddr @trusted_ipv4 ct state new limit rate 300/second burst 500 accept
        tcp dport $PGB_PORT ip  saddr @trusted_ipv4 accept
        tcp dport $PGB_PORT ip6 saddr @trusted_ipv6 ct state new limit rate 300/second burst 500 accept
        tcp dport $PGB_PORT ip6 saddr @trusted_ipv6 accept

        # SYN flood basico
        tcp flags syn ct state new limit rate 100/second burst 200 accept
        tcp flags syn ct state new drop

        # Logging (limitado)
        tcp dport $PG_PORT log prefix "PG-BLOCK " limit rate 5/minute drop
        tcp dport $PGB_PORT log prefix "PGB-BLOCK " limit rate 5/minute drop
    }
    chain forward { type filter hook forward priority 0; policy drop; }
    chain output  { type filter hook output  priority 0; policy accept; }
}
EOF

# Validar y cargar
nft -c -f "$NFT_FILE" || abort "Sintaxis nftables inválida"
nft -f "$NFT_FILE"
systemctl enable --now nftables

# ------------------------------------------------------------------------------
# FAIL2BAN / LOGGING / MONITOR (igual que antes)
# ------------------------------------------------------------------------------
mkdir -p /var/log/nftables
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
backend   = systemd
banaction = nftables-multiport
bantime   = 86400
findtime  = 600
maxretry  = 3
[postgresql]
enabled = true
filter  = postgresql
port    = 5432
journalmatch = _SYSTEMD_UNIT=postgresql.service
[pgbouncer]
enabled = true
filter  = pgbouncer
port    = 6432
logpath = /var/log/postgresql/pgbouncer.log
EOF
systemctl enable --now fail2ban

cat > /etc/rsyslog.d/30-nftables.conf <<EOF
if \$msg contains 'PG-BLOCK' or \$msg contains 'PGB-BLOCK' then /var/log/nftables/nftables.log
& stop
EOF
systemctl restart rsyslog

# Monitor rápido
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

log "Configuración finalizada. Backups en: $BACKUP_DIR"
echo "Comandos útiles:"
echo "  Reglas nftables : nft list ruleset"
echo "  Monitor         : $MONITOR"
