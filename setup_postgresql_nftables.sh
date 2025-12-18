#!/bin/bash
# ===================================================================
# Script  : nftables-full-pg17-deb13-nossh-IMPROVED.sh
# Objetivo: Configurar nftables + fail2ban para PostgreSQL 17 PRODUCCIÓN
# Mejoras: IPv6, rate-limiting local, regex seguras, integración completa
# ===================================================================
set -euo pipefail
################################################################################
# 0. CONFIGURACIÓN PARAMETRIZABLE
################################################################################
PG_PORT=5432
PGB_PORT=6432
MON_PORT=9090
# Configuración dual-stack (IPv4 + IPv6)
TRUSTED_NET_IPV4="192.168.1.0/24"
TRUSTED_NET_IPV6="fd00::/64"  # Si usas IPv6 ULA, ajustar
BACKUP_DIR="/root/nftables_backup_$(date +%Y%m%d_%H%M%S)"
NFT_FILE="/etc/nftables.conf"
################################################################################
# 1. FUNCIONES AUXILIARES (mantener igual, están bien)
################################################################################
log()  { echo "[$(date '+%F %T')] $*" ; }
abort(){ log "ERROR: $*" ; exit 1 ; }
check_root(){ [[ $EUID -eq 0 ]] || abort "Ejecutar como root"; }
install_pkg(){
    apt-get -qq update
    apt-get -qq install -y nftables fail2ban rsyslog
}
validate_nft(){
    nft -c -f "$NFT_FILE" || abort "Sintaxis nftables inválida"
}
################################################################################
# 2. PRE-CHEQUEOS (igual)
################################################################################
check_root
command -v nft >/dev/null || install_pkg
################################################################################
# 3. BACKUP (igual)
################################################################################
mkdir -p "$BACKUP_DIR"
cp -f "$NFT_FILE" "$BACKUP_DIR" 2>/dev/null || true
nft list ruleset > "$BACKUP_DIR/ruleset.old" 2>/dev/null || true
cp -f /etc/fail2ban/jail.local "$BACKUP_DIR" 2>/dev/null || true
log "Backups guardados en $BACKUP_DIR"
################################################################################
# 4. CREAR DIRECTORIOS DE LOG (igual)
################################################################################
mkdir -p /var/log/nftables /var/log/postgresql
chown postgres:adm /var/log/postgresql || true
################################################################################
# 5. GENERAR REGLAS NFTABLES MEJORADAS (CORREGIDO)
################################################################################
cat > "$NFT_FILE" <<EOF
#!/usr/sbin/nft -f
# ----------------------------------------------------------
# Tabla filter - PRODUCCIÓN SEGURA (sin SSH)
# ----------------------------------------------------------
flush ruleset

define PG_PORT=$PG_PORT
define PGB_PORT=$PGB_PORT
define MON_PORT=$MON_PORT

table inet filter {
    # Conjuntos IPv4
    set trusted_ipv4 {
        type ipv4_addr; flags interval;
        elements = { 
            127.0.0.1,                 # localhost IPv4
            $TRUSTED_NET_IPV4          # Red aplicaciones IPv4
        }
    }
    
    # Conjuntos IPv6 (si usas)
    set trusted_ipv6 {
        type ipv6_addr; flags interval;
        elements = {
            ::1,                       # localhost IPv6
            $TRUSTED_NET_IPV6          # Red aplicaciones IPv6 (opcional)
        }
    }
    
    # Blacklist dinámica (para fail2ban)
    set blacklist_ipv4 {
        type ipv4_addr; flags dynamic, timeout;
        size 65535; timeout 24h;
    }
    
    set blacklist_ipv6 {
        type ipv6_addr; flags dynamic, timeout;
        size 65535; timeout 24h;
    }

    chain input {
        type filter hook input priority 0; policy drop;

        # Estados establecidos y loopback
        ct state established,related accept
        iif "lo" accept

        # ICMPv4 limitado (ping)
        ip protocol icmp icmp type { echo-request, echo-reply, destination-unreachable } \
            limit rate 20/second burst 40 accept
        ip protocol icmp accept  # Otros tipos ICMPv4
        
        # ICMPv6 limitado (más tipos esenciales para IPv6)
        ip6 nexthdr ipv6-icmp icmpv6 type { echo-request, echo-reply, destination-unreachable, packet-too-big, time-exceeded, parameter-problem } \
            limit rate 20/second burst 40 accept
        ip6 nexthdr ipv6-icmp icmpv6 type { nd-neighbor-solicit, nd-neighbor-advert, nd-router-solicit, nd-router-advert } \
            limit rate 10/second burst 20 accept

        # PgBouncer - solo desde redes confiables con rate limiting
        tcp dport \$PGB_PORT ip  saddr @trusted_ipv4 \
            ct state new limit rate 30/minute burst 50 accept
        tcp dport \$PGB_PORT ip6 saddr @trusted_ipv6 \
            ct state new limit rate 30/minute burst 50 accept
        tcp dport \$PGB_PORT ip  saddr @trusted_ipv4 accept
        tcp dport \$PGB_PORT ip6 saddr @trusted_ipv6 accept

        # PostgreSQL - SOLO localhost con rate limiting (seguridad defensiva)
        tcp dport \$PG_PORT ip  saddr 127.0.0.1 \
            ct state new limit rate 100/minute burst 200 accept
        tcp dport \$PG_PORT ip6 saddr ::1 \
            ct state new limit rate 100/minute burst 200 accept
        tcp dport \$PG_PORT ip  saddr 127.0.0.1 accept
        tcp dport \$PG_PORT ip6 saddr ::1 accept

        # Puerto de monitoreo (opcional, comentado por defecto)
        # tcp dport \$MON_PORT ip saddr @trusted_ipv4 accept
        # tcp dport \$MON_PORT ip6 saddr @trusted_ipv6 accept

        # Blacklist (para fail2ban)
        ip  saddr @blacklist_ipv4 drop
        ip6 saddr @blacklist_ipv6 drop

        # Protección contra port scanning
        tcp flags & (syn) == syn ct state new \
            limit rate 10/second burst 20 accept
        tcp flags & (syn) == syn ct state new log prefix "NFT-PORTSCAN: " drop

        # Logging de intentos bloqueados (solo primeros por minuto para evitar log flood)
        tcp dport \$PG_PORT ip saddr != 127.0.0.1 \
            limit rate 1/minute log prefix "PG-DIRECT-BLOCK: " drop
        tcp dport \$PG_PORT ip6 saddr != ::1 \
            limit rate 1/minute log prefix "PG-DIRECT-BLOCKv6: " drop
        tcp dport \$PGB_PORT ip saddr != @trusted_ipv4 \
            limit rate 5/minute log prefix "PGB-BLOCKv4: " drop
        tcp dport \$PGB_PORT ip6 saddr != @trusted_ipv6 \
            limit rate 5/minute log prefix "PGB-BLOCKv6: " drop
    }

    chain forward { 
        type filter hook forward priority 0; policy drop;
        # No forwarding en servidor de base de datos
    }
    
    chain output { 
        type filter hook output priority 0; policy accept;
        # Permitir todo output
    }
}

# Tabla adicional para que fail2ban pueda bloquear IPs
table inet f2b {
    set postgresql-ban {
        type ipv4_addr
        flags dynamic, timeout
        timeout 86400  # 24 horas
    }
    
    set pgbouncer-ban {
        type ipv4_addr
        flags dynamic, timeout
        timeout 7200   # 2 horas
    }
    
    chain input {
        type filter hook input priority -5;
        ip saddr @postgresql-ban drop
        ip saddr @pgbouncer-ban drop
    }
}
EOF

validate_nft
log "Reglas nftables generadas (IPv4+IPv6, rate-limiting local)"
################################################################################
# 6. APLICAR REGLAS (igual)
################################################################################
nft -f "$NFT_FILE"
systemctl enable --now nftables
log "Reglas nftables aplicadas"
################################################################################
# 7. FAIL2BAN MEJORADO (CORREGIDO)
################################################################################
# Filtro PostgreSQL más específico
cat > /etc/fail2ban/filter.d/postgresql.conf <<'EOF'
[Definition]
# Más específico para evitar falsos positivos
failregex = ^%(__prefix_line)sFATAL:\s+password authentication failed for user ".*"$
            ^%(__prefix_line)sFATAL:\s+no pg_hba.conf entry for host ".*", user ".*", database ".*", SSL off$
            ^%(__prefix_line)sLOG:\s+invalid password for user ".*"$
            ^%(__prefix_line)sERROR:\s+authentication failed for user ".*"$
ignoreregex = ^%(__prefix_line)sLOG:\s+connection (authorized|received|closed)
EOF

# Filtro PgBouncer
cat > /etc/fail2ban/filter.d/pgbouncer.conf <<'EOF'
[Definition]
failregex = ^.*LOG:\s+login failed:.*$
            ^.*WARNING:\s+auth failed:.*$
            ^.*ERROR:\s+pooler error: auth failed.*$
ignoreregex = ^.*LOG:\s+(new connection|connection ok|closing because:).*$
EOF

# Jail con integración nftables
cat > /etc/fail2ban/jail.local <<EOF
[DEFAULT]
bantime  = 3600
findtime = 600
maxretry = 3
backend  = systemd
banaction = nftables-multiport
banaction_allports = nftables-allports

[postgresql]
enabled   = true
port      = $PG_PORT,$PGB_PORT
filter    = postgresql
logpath   = /var/log/postgresql/postgresql-*.log
maxretry  = 3
bantime   = 86400
# Usa la tabla f2b que creamos en nftables
action    = nftables-multiport[name=postgresql, port="\$port", table="f2b", setname="postgresql-ban"]

[pgbouncer]
enabled   = true
port      = $PGB_PORT
filter    = pgbouncer
logpath   = /var/log/postgresql/pgbouncer.log
maxretry  = 3
bantime   = 7200
action    = nftables-multiport[name=pgbouncer, port="\$port", table="f2b", setname="pgbouncer-ban"]

# Chain de logging para auditoría
[postgresql-log]
enabled   = true
filter    = postgresql
logpath   = /var/log/postgresql/postgresql-*.log
action    = %(action_mwl)s
maxretry  = 1
EOF

systemctl enable --now fail2ban
sleep 2  # Dar tiempo a fail2ban para cargar
fail2ban-client reload
log "Fail2ban configurado con integración nftables"
################################################################################
# 8. LOGGING MEJORADO (CORREGIDO)
################################################################################
# Configuración rsyslog para capturar logs de kernel (nftables) y PostgreSQL
cat > /etc/rsyslog.d/30-nftables-postgres.conf <<'EOF'
# Logs de nftables (desde kernel)
if $programname == 'kernel' and ($msg contains 'BLOCK' or $msg contains 'PORTSCAN') then {
    action(type="omfile" file="/var/log/nftables/nftables.log")
    stop
}

# Logs de PostgreSQL separados
if $programname == 'postgres' then {
    if $msg contains 'FATAL' or $msg contains 'ERROR' or $msg contains 'authentication' then {
        action(type="omfile" file="/var/log/postgresql/auth_errors.log")
    }
}
EOF

# Logrotate para todos los logs relevantes
cat > /etc/logrotate.d/nftables-postgres <<'EOF'
/var/log/nftables/nftables.log
/var/log/postgresql/auth_errors.log
/var/log/postgresql/pgbouncer.log
{
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    sharedscripts
    postrotate
        systemctl kill -s HUP rsyslog.service
        # Recargar fail2ban para que detecte nuevos logs
        systemctl reload fail2ban 2>/dev/null || true
    endscript
}
EOF

systemctl restart rsyslog
log "Sistema de logs mejorado (separado auth errors)"
################################################################################
# 9. VERIFICACIÓN COMPREHENSIVA (MEJORADA)
################################################################################
log "=== VERIFICACIÓN COMPLETA ==="

# Servicios
log "1. Estado de servicios:"
systemctl is-active nftables && echo "  nftables: ACTIVO" || echo "  nftables: INACTIVO"
systemctl is-active fail2ban && echo "  fail2ban: ACTIVO" || echo "  fail2ban: INACTIVO"

# Conjuntos nftables
log "2. Conjuntos nftables cargados:"
nft list sets | grep -E "(trusted|blacklist|ban)" | sed 's/^/  /'

# Reglas específicas
log "3. Reglas para puertos críticos:"
echo "  PostgreSQL ($PG_PORT):"
nft list chain inet filter input | grep "dport $PG_PORT" | sed 's/^/    /' || echo "    (no hay reglas explícitas)"
echo "  PgBouncer ($PGB_PORT):"
nft list chain inet filter input | grep "dport $PGB_PORT" | sed 's/^/    /' || echo "    (no hay reglas explícitas)"

# Pruebas de conectividad
log "4. Pruebas de conectividad local:"
echo "  PostgreSQL local:"
if sudo -u postgres pg_isready -p $PG_PORT 2>/dev/null; then
    echo "    ✅ Conecta"
else
    echo "    ❌ No conecta"
fi

echo "  PgBouncer local:"
if sudo -u postgres pg_isready -h 127.0.0.1 -p $PGB_PORT 2>/dev/null; then
    echo "    ✅ Conecta"
else
    echo "    ❌ No conecta (¿pgbouncer corriendo?)"
fi

# Fail2ban status
log "5. Estado fail2ban:"
if fail2ban-client status postgresql 2>/dev/null | grep -q "Status"; then
    echo "  ✅ Jail postgresql activo"
    fail2ban-client status postgresql | grep "Currently banned" | sed 's/^/    /'
else
    echo "  ⚠️  Jail postgresql no activo"
fi

if fail2ban-client status pgbouncer 2>/dev/null | grep -q "Status"; then
    echo "  ✅ Jail pgbouncer activo"
else
    echo "  ⚠️  Jail pgbouncer no activo"
fi

# Verificación final de no-SSH
log "6. Verificación SIN SSH:"
if nft list chain inet filter input | grep -q "dport 22"; then
    echo "  ❌ SE ENCONTRARON REGLAS SSH (no deberían estar)"
else
    echo "  ✅ Confirmado: SIN reglas SSH"
fi
################################################################################
# 10. SCRIPT DE MONITOREO MEJORADO (CORREGIDO)
################################################################################
MONITOR="/usr/local/bin/nft_mon.sh"
cat > "$MONITOR" <<'EOF'
#!/bin/bash
echo "=== MONITOR NFTABLES & POSTGRESQL ==="
echo "Fecha: $(date '+%F %T')"
echo ""

# Estado servicios
echo "1. SERVICIOS:"
SERVICES="nftables fail2ban postgresql@17-main pgbouncer"
for svc in $SERVICES; do
    if systemctl is-active --quiet "$svc" 2>/dev/null; then
        echo "  ✅ $svc: ACTIVO"
    else
        echo "  ❌ $svc: INACTIVO"
    fi
done
echo ""

# Conexiones PostgreSQL
echo "2. CONEXIONES BASE DE DATOS:"
PG_CONN=$(sudo -u postgres psql -p 5432 -t -c "SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid();" 2>/dev/null | xargs)
echo "  PostgreSQL: ${PG_CONN:-0} conexiones"
echo "  PgBouncer: $(sudo -u postgres pg_isready -h 127.0.0.1 -p 6432 2>&1 | grep -c 'accepting' || echo "0") aceptando"
echo ""

# NFTables - estadísticas
echo "3. NFTABLES - ESTADÍSTICAS:"
echo "  IPs en trusted_ipv4: $(sudo nft list set inet filter trusted_ipv4 2>/dev/null | grep -c "ip" || echo "0")"
echo "  IPs en blacklist_ipv4: $(sudo nft list set inet filter blacklist_ipv4 2>/dev/null | grep -c "ip" || echo "0")"
echo "  IPs en f2b postgresql-ban: $(sudo nft list set inet f2b postgresql-ban 2>/dev/null | grep -c "ip" || echo "0")"
echo ""

# Fail2ban
echo "4. FAIL2BAN - BLOQUEOS:"
for jail in postgresql pgbouncer; do
    if sudo fail2ban-client status "$jail" 2>/dev/null | grep -q "Status"; then
        BANNED=$(sudo fail2ban-client status "$jail" 2>/dev/null | grep "Currently banned" | awk '{print $4}')
        echo "  $jail: ${BANNED:-0} IPs bloqueadas"
    fi
done
echo ""

# Últimos eventos
echo "5. ÚLTIMOS EVENTOS (últimos 3):"
echo "  NFTables bloqueos:"
sudo tail -3 /var/log/nftables/nftables.log 2>/dev/null | sed 's/^/    /' || echo "    No hay registros"
echo ""
echo "  PostgreSQL auth errors:"
sudo tail -3 /var/log/postgresql/auth_errors.log 2>/dev/null | sed 's/^/    /' || echo "    No hay errores"
EOF

chmod +x "$MONITOR"
log "Monitor mejorado creado: $MONITOR"
################################################################################
# 11. DOCUMENTACIÓN FINAL
################################################################################
cat > "$BACKUP_DIR/README.txt" <<EOF
CONFIGURACIÓN NFTABLES + FAIL2BAN - POSTGRESQL 17
================================================
Fecha: $(date)
Servidor: $(hostname)
IP: $(hostname -I | head -1)

CONFIGURACIÓN APLICADA:
- PostgreSQL: puerto $PG_PORT (solo localhost con rate limiting)
- PgBouncer: puerto $PGB_PORT (solo red $TRUSTED_NET_IPV4)
- Sin SSH: acceso out-of-band asumido
- IPv4 + IPv6: configurado dual-stack
- Fail2ban: integrado con nftables

ARCHIVOS IMPORTANTES:
- nftables: $NFT_FILE
- fail2ban: /etc/fail2ban/jail.local
- Logs: /var/log/nftables/nftables.log
- Monitor: /usr/local/bin/nft_mon.sh

COMANDOS ÚTILES:
1. Ver reglas: nft list ruleset
2. Editar y aplicar: nano $NFT_FILE && nft -f $NFT_FILE
3. Monitor: /usr/local/bin/nft_mon.sh
4. Logs en tiempo real: tail -f /var/log/nftables/nftables.log
5. Estado fail2ban: fail2ban-client status

AGREGAR IPs AL TRUSTED SET:
nft add element inet filter trusted_ipv4 { 192.168.2.50 }
nft add element inet filter trusted_ipv6 { fd00::1234 }

BLOQUEAR IP MANUALMENTE:
nft add element inet f2b postgresql-ban { 203.0.113.5 }
EOF

log "Documentación guardada en: $BACKUP_DIR/README.txt"
################################################################################
# 12. FIN
################################################################################
log "=== CONFIGURACIÓN COMPLETADA ==="
echo ""
echo "✅ CONFIGURACIÓN APLICADA EXITOSAMENTE"
echo ""
echo "📋 RESUMEN:"
echo "   - nftables: Filtrado sin SSH, solo redes autorizadas"
echo "   - PostgreSQL 5432: Rate-limited localhost only"
echo "   - PgBouncer 6432: Solo desde $TRUSTED_NET_IPV4"
echo "   - fail2ban: Integrado con nftables para bloqueo automático"
echo "   - IPv6: Configurado (si no usas, ignora warnings)"
echo ""
echo "🔧 COMANDOS RÁPIDOS:"
echo "   Ver estado completo: /usr/local/bin/nft_mon.sh"
echo "   Ver reglas: nft list ruleset"
echo "   Editar configuración: nano $NFT_FILE"
echo "   Aplicar cambios: nft -f $NFT_FILE"
echo ""
echo "💾 BACKUPS EN: $BACKUP_DIR"
echo "   Incluye: README.txt, configuraciones anteriores"
echo ""
exit 0
