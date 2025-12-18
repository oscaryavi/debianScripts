#!/bin/bash
set -euo pipefail

PG_PORT=5432
PGB_PORT=6432

TRUSTED_IPV4="192.168.1.0/24"
TRUSTED_IPV6="fd00::/64"

NFT_FILE="/etc/nftables.conf"

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

        # ICMPv4
        ip protocol icmp limit rate 20/second burst 40 accept

        # ICMPv6
        ip6 nexthdr ipv6-icmp icmpv6 type {
            echo-request, echo-reply,
            destination-unreachable, packet-too-big,
            time-exceeded, parameter-problem,
            nd-neighbor-solicit, nd-neighbor-advert,
            nd-router-solicit, nd-router-advert
        } limit rate 20/second burst 40 accept

        # PostgreSQL solo localhost
        tcp dport \$PG_PORT ip  saddr 127.0.0.1 accept
        tcp dport \$PG_PORT ip6 saddr ::1 accept

        # PgBouncer redes confiables (rate-limit correcto)
        tcp dport \$PGB_PORT ip  saddr @trusted_ipv4 ct state new \
            limit rate 300/second burst 500 accept
        tcp dport \$PGB_PORT ip6 saddr @trusted_ipv6 ct state new \
            limit rate 300/second burst 500 accept

        tcp dport \$PGB_PORT ip  saddr @trusted_ipv4 accept
        tcp dport \$PGB_PORT ip6 saddr @trusted_ipv6 accept

        # Protección SYN
        tcp flags syn ct state new limit rate 100/second burst 200 accept
        tcp flags syn ct state new drop

        # Logs
        tcp dport \$PG_PORT  limit rate 1/minute counter log prefix "PG-BLOCK " drop
        tcp dport \$PGB_PORT limit rate 5/minute counter log prefix "PGB-BLOCK " drop
    }

    chain forward { type filter hook forward priority 0; policy drop; }
    chain output  { type filter hook output  priority 0; policy accept; }
}
EOF

# Validación y carga
nft -c -f "$NFT_FILE"
nft -f "$NFT_FILE"
systemctl enable --now nftables

echo "✔ nftables cargado correctamente"
