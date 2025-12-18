#!/bin/bash
# =============================================
# SCRIPT COMPLETO NFTABLES PARA POSTGRESQL
# Debian 13 + PostgreSQL 17 + PgBouncer
# Incluye: Seguridad, Monitoreo, Fail2ban, Logging
# =============================================

echo "============================================="
echo "CONFIGURACIÓN COMPLETA NFTABLES POSTGRESQL"
echo "Fecha: $(date)"
echo "PostgreSQL: 5432, PgBouncer: 6432, SSH: 22"
echo "============================================="
echo ""

# ========= 1. DETECCIÓN DEL SISTEMA =========
echo "1. DETECTANDO SISTEMA..."
OS=$(lsb_release -si 2>/dev/null || echo "Debian")
VERSION=$(lsb_release -sr 2>/dev/null || echo "13")
IP_SERVER=$(hostname -I | awk '{print $1}')
NETWORK=$(ip route | grep -oP '(\d+\.\d+\.\d+\.\d+/\d+)' | head -1)

echo "   Sistema: $OS $VERSION"
echo "   IP Servidor: $IP_SERVER"
echo "   Red detectada: $NETWORK"
echo ""

# ========= 2. INSTALACIÓN DEPENDENCIAS =========
echo "2. INSTALANDO DEPENDENCIAS..."
sudo apt update
sudo apt install -y nftables fail2ban net-tools

# Verificar servicios PostgreSQL
if ! systemctl is-active --quiet postgresql@17-main; then
    echo "   ⚠️  PostgreSQL 17 no está activo"
else
    echo "   ✅ PostgreSQL 17 activo en puerto 5432"
fi

if ! systemctl is-active --quiet pgbouncer; then
    echo "   ⚠️  PgBouncer no está activo"
else
    echo "   ✅ PgBouncer activo en puerto 6432"
fi
echo ""

# ========= 3. BACKUP CONFIGURACIÓN ACTUAL =========
echo "3. CREANDO BACKUPS..."
BACKUP_DIR="/root/nftables_backup_$(date +%Y%m%d_%H%M%S)"
sudo mkdir -p "$BACKUP_DIR"

# Backup nftables actual
sudo cp /etc/nftables.conf "$BACKUP_DIR/nftables.conf.old" 2>/dev/null
sudo nft list ruleset > "$BACKUP_DIR/ruleset.old" 2>/dev/null

# Backup fail2ban
sudo cp /etc/fail2ban/jail.local "$BACKUP_DIR/jail.local.old" 2>/dev/null 2>/dev/null

echo "   ✅ Backups creados en: $BACKUP_DIR"
echo ""

# ========= 4. CONFIGURACIÓN NFTABLES COMPLETA =========
echo "4. CONFIGURANDO NFTABLES COMPLETO..."

# Crear configuración principal
sudo tee /etc/nftables.conf > /dev/null << 'NFT_MAIN'
#!/usr/sbin/nft -f

# =============================================
# NFTABLES - CONFIGURACIÓN COMPLETA POSTGRESQL
# =============================================

flush ruleset

# Variables globales
define DB_PORT = 5432          # PostgreSQL
define PGBOUNCER_PORT = 6432   # PgBouncer
define SSH_PORT = 22           # SSH
define MONITOR_PORT = 9090     # Puerto monitoreo (opcional)

# ========= TABLA PRINCIPAL =========
table inet filter {
    # ========= CONJUNTOS DE IPs =========
    set trusted_ips {
        type ipv4_addr
        flags interval
        # ========= ¡EDITA ESTAS IPs! =========
        elements = {
            127.0.0.1,                 # localhost
            192.168.1.0/24,            # Red LAN (cambia según tu red)
            # 10.0.0.0/8,              # Red interna (opcional)
            # 172.16.0.0/12,           # Otra red interna
            # Agrega IPs específicas de tus servidores:
            # 192.168.1.100,           # Servidor App 1
            # 192.168.1.101,           # Servidor App 2
            # 203.0.113.50,            # IP pública específica
        }
    }

    set admin_ips {
        type ipv4_addr
        # IPs para administración SSH
        elements = {
            192.168.1.0/24,            # Solo desde LAN
            # 203.0.113.100/32,        # IP pública de admin
        }
    }

    set blacklist {
        type ipv4_addr
        flags dynamic, timeout
        timeout 24h
        size 65535
    }

    # ========= CHAIN INPUT (ENTRADA) =========
    chain input {
        type filter hook input priority 0; policy drop;

        # 1. Conexiones establecidas y relacionadas
        ct state established,related accept

        # 2. Loopback (totalmente permitido)
        iif "lo" accept

        # 3. ICMP (ping) - limitado
        ip protocol icmp icmp type { echo-request, echo-reply } limit rate 10/second burst 20 packets accept
        ip protocol icmp accept

        # 4. SSH - solo desde IPs de administración + rate limiting
        tcp dport $SSH_PORT ip saddr @admin_ips ct state new limit rate 3/minute burst 5 packets accept
        tcp dport $SSH_PORT ip saddr @admin_ips accept

        # 5. PgBouncer (6432) - solo desde IPs confiables + rate limiting
        tcp dport $PGBOUNCER_PORT ip saddr @trusted_ips ct state new limit rate 30/minute burst 50 packets accept
        tcp dport $PGBOUNCER_PORT ip saddr @trusted_ips accept

        # 6. PostgreSQL (5432) - EXCLUSIVAMENTE localhost
        tcp dport $DB_PORT ip saddr 127.0.0.1 accept
        tcp dport $DB_PORT ip saddr ::1 accept  # IPv6 localhost

        # 7. Monitoreo (si usas Prometheus/Grafana)
        # tcp dport $MONITOR_PORT ip saddr @trusted_ips accept

        # 8. Bloquear IPs en lista negra
        ip saddr @blacklist drop

        # 9. Protección contra escaneo de puertos
        tcp flags syn ct state new limit rate 5/second burst 10 packets accept
        tcp flags syn ct state new log prefix "PORT-SCAN: " drop

        # 10. Logging de intentos bloqueados
        tcp dport $DB_PORT ip saddr != 127.0.0.1 log prefix "DIRECT-PG-BLOCK: " group 0 drop
        tcp dport $PGBOUNCER_PORT ip saddr != @trusted_ips log prefix "PGBOUNCER-BLOCK: " group 0 drop
        tcp dport $SSH_PORT ip saddr != @admin_ips log prefix "SSH-BLOCK: " group 0 drop
    }

    # ========= CHAIN FORWARD (REENVÍO) =========
    chain forward {
        type filter hook forward priority 0; policy drop;
        # No permitimos reenvío en servidor de base de datos
    }

    # ========= CHAIN OUTPUT (SALIDA) =========
    chain output {
        type filter hook output priority 0; policy accept;
        # Permitir todo lo que sale del servidor
    }

    # ========= CHAIN PARA BLACKLIST AUTOMÁTICO =========
    chain auto_blacklist {
        type filter hook input priority -10;

        # Agregar a blacklist IPs que intentan muchas conexiones
        tcp dport $PGBOUNCER_PORT ct state new ip saddr & 0.0.0.0 {
            add @blacklist { ip saddr timeout 1h }
            log prefix "AUTO-BLACKLIST-PG: " group 0
        }

        tcp dport $SSH_PORT ct state new ip saddr & 0.0.0.0 {
            add @blacklist { ip saddr timeout 24h }
            log prefix "AUTO-BLACKLIST-SSH: " group 0
        }
    }
}

# ========= TABLA PARA NAT (si necesitas) =========
table ip nat {
    chain prerouting {
        type nat hook prerouting priority -100;
    }

    chain postrouting {
        type nat hook postrouting priority 100;
    }
}

# ========= TABLA PARA MONITOREO DETALLADO =========
table inet monitor {
    chain log_detailed {
        type filter hook input priority -100;

        # Log detallado para análisis
        tcp dport $DB_PORT log prefix "PG-TRAFFIC: " group 1
        tcp dport $PGBOUNCER_PORT log prefix "PGBOUNCER-TRAFFIC: " group 1
        tcp dport $SSH_PORT log prefix "SSH-TRAFFIC: " group 1
    }
}
NFT_MAIN

echo "   ✅ Configuración nftables creada"
echo ""

# ========= 5. CONFIGURAR FAIL2BAN PARA POSTGRESQL =========
echo "5. CONFIGURANDO FAIL2BAN..."

# Crear filtro para PostgreSQL
sudo tee /etc/fail2ban/filter.d/postgresql.conf > /dev/null << 'FAIL2BAN_FILTER'
[Definition]
failregex = ^%(__prefix_line)sFATAL:.*password authentication failed for user.*
            ^%(__prefix_line)sFATAL:.*no pg_hba.conf entry for.*
            ^%(__prefix_line)sLOG:.*invalid password for user.*
            ^%(__prefix_line)sERROR:.*failed to authenticate.*
ignoreregex =
FAIL2BAN_FILTER

# Crear filtro para PgBouncer
sudo tee /etc/fail2ban/filter.d/pgbouncer.conf > /dev/null << 'PGBOUNCER_FILTER'
[Definition]
failregex = ^.*LOG.* login failed:.*
            ^.*WARNING.* auth failed.*
            ^.*ERROR.* pooler error:.*
ignoreregex =
PGBOUNCER_FILTER

# Configurar jail principal
sudo tee /etc/fail2ban/jail.local > /dev/null << 'FAIL2BAN_JAIL'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = auto
action = %(action_)s

[sshd]
enabled = true
port = ssh
filter = sshd
logpath = /var/log/auth.log
maxretry = 3

[postgresql]
enabled = true
port = 5432,6432
filter = postgresql
logpath = /var/log/postgresql/postgresql-*.log
maxretry = 3
bantime = 86400

[pgbouncer]
enabled = true
port = 6432
filter = pgbouncer
logpath = /var/log/postgresql/pgbouncer.log
maxretry = 3
bantime = 7200

[postgresql-nft]
enabled = true
filter = postgresql
action = nftables-multiport[name=POSTGRES, port="5432,6432"]
logpath = /var/log/postgresql/postgresql-*.log
maxretry = 3
bantime = 3600
FAIL2BAN_JAIL

echo "   ✅ Fail2ban configurado"
echo ""

# ========= 6. CONFIGURAR LOGGING =========
echo "6. CONFIGURANDO SISTEMA DE LOGS..."

# Crear directorio de logs personalizado
sudo mkdir -p /var/log/nftables

# Configurar rsyslog para nftables
sudo tee /etc/rsyslog.d/30-nftables.conf > /dev/null << 'SYSLOG_CONFIG'
if $programname == 'nftables' then /var/log/nftables/nftables.log
& stop
SYSLOG_CONFIG

# Configurar logrotate
sudo tee /etc/logrotate.d/nftables > /dev/null << 'LOGROTATE_CONFIG'
/var/log/nftables/nftables.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 640 root adm
    postrotate
        /usr/bin/systemctl kill -s HUP rsyslog.service
    endscript
}
LOGROTATE_CONFIG

# Configurar logrotate para PostgreSQL
sudo tee /etc/logrotate.d/postgresql-nft > /dev/null << 'PG_LOGROTATE'
/var/log/postgresql/postgresql-*.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    create 640 postgres adm
    sharedscripts
    postrotate
        /usr/bin/systemctl reload postgresql@17-main
    endscript
}
PG_LOGROTATE

echo "   ✅ Sistema de logs configurado"
echo ""

# ========= 7. APLICAR CONFIGURACIÓN =========
echo "7. APLICANDO CONFIGURACIÓN..."

# Aplicar nftables
sudo nft -f /etc/nftables.conf

# Hacer persistente
sudo nft list ruleset > /etc/nftables.conf
sudo systemctl restart nftables
sudo systemctl enable nftables

# Configurar fail2ban
sudo systemctl restart fail2ban
sudo systemctl enable fail2ban

# Reiniciar rsyslog
sudo systemctl restart rsyslog

echo "   ✅ Configuración aplicada y persistente"
echo ""

# ========= 8. VERIFICACIÓN COMPLETA =========
echo "8. VERIFICANDO CONFIGURACIÓN..."
echo ""

echo "   a) Estado servicios:"
sudo systemctl status nftables --no-pager | grep -E "(Active:|Loaded:)"
sudo systemctl status fail2ban --no-pager | grep -E "(Active:|Loaded:)"
echo ""

echo "   b) Reglas nftables activas:"
echo "      PostgreSQL (5432):"
sudo nft list chain inet filter input | grep "5432" || echo "      No encontradas (puede ser normal)"
echo ""
echo "      PgBouncer (6432):"
sudo nft list chain inet filter input | grep "6432" || echo "      No encontradas"
echo ""
echo "      SSH (22):"
sudo nft list chain inet filter input | grep "22" || echo "      No encontradas"
echo ""

echo "   c) Conjuntos de IPs:"
sudo nft list set inet filter trusted_ips
sudo nft list set inet filter admin_ips
echo ""

echo "   d) Pruebas de conectividad:"
echo "      Localhost → PostgreSQL (5432):"
sudo -u postgres pg_isready -p 5432 2>&1 | sed 's/^/        /'
echo ""
echo "      Localhost → PgBouncer (6432):"
sudo -u postgres pg_isready -h 127.0.0.1 -p 6432 2>&1 | sed 's/^/        /'
echo ""

echo "   e) Fail2ban status:"
sudo fail2ban-client status | grep -E "(postgresql|pgbouncer|sshd)" || echo "      No hay jails activas"
echo ""

# ========= 9. SCRIPT DE MONITOREO =========
echo "9. CREANDO SCRIPT DE MONITOREO..."

sudo tee /usr/local/bin/monitor_nftables.sh > /dev/null << 'MONITOR_SCRIPT'
#!/bin/bash
echo "=== MONITOR NFTABLES & POSTGRESQL ==="
echo "Fecha: $(date)"
echo ""

# 1. Estado servicios
echo "1. SERVICIOS:"
echo "   nftables: $(systemctl is-active nftables)"
echo "   fail2ban: $(systemctl is-active fail2ban)"
echo "   postgresql: $(systemctl is-active postgresql@17-main)"
echo "   pgbouncer: $(systemctl is-active pgbouncer)"
echo ""

# 2. Conexiones activas
echo "2. CONEXIONES ACTIVAS:"
echo "   PostgreSQL:"
sudo -u postgres psql -p 5432 -t -c "SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid();" 2>/dev/null || echo "      No conecta"
echo ""
echo "   PgBouncer:"
psql -h 127.0.0.1 -p 6432 -U pgbouncer pgbouncer -t -c "SHOW CLIENTS;" 2>/dev/null | wc -l | awk '{print "      Clientes: " $1}' || echo "      No conecta"
echo ""

# 3. Estadísticas nftables
echo "3. NFTABLES - ÚLTIMOS BLOQUEOS:"
sudo nft list ruleset -a 2>/dev/null | grep -E "BLOCK|DROP" | tail -5 | sed 's/^/   /'
echo ""

# 4. IPs bloqueadas por fail2ban
echo "4. FAIL2BAN - IPs BLOQUEADAS:"
sudo fail2ban-client status postgresql 2>/dev/null | grep -i "banned" || echo "   Ninguna"
sudo fail2ban-client status pgbouncer 2>/dev/null | grep -i "banned" || echo "   Ninguna"
echo ""

# 5. Logs recientes
echo "5. LOGS RECIENTES (últimas 5 líneas):"
echo "   nftables:"
sudo tail -5 /var/log/nftables/nftables.log 2>/dev/null || echo "      No hay logs"
echo ""
echo "   PostgreSQL:"
sudo tail -5 /var/log/postgresql/postgresql-17-main.log 2>/dev/null | grep -E "(FATAL|ERROR)" || echo "      Sin errores"
MONITOR_SCRIPT

sudo chmod +x /usr/local/bin/monitor_nftables.sh

echo "   ✅ Script de monitoreo creado: /usr/local/bin/monitor_nftables.sh"
echo ""

# ========= 10. INSTRUCCIONES FINALES =========
echo "10. INSTRUCCIONES FINALES:"
echo "============================================="
echo ""
echo "✅ CONFIGURACIÓN COMPLETADA"
echo ""
echo "📋 RESUMEN IMPLEMENTADO:"
echo "   1. NFTables: Filtrado completo de red"
echo "   2. PostgreSQL 5432: Solo localhost"
echo "   3. PgBouncer 6432: Solo IPs en 'trusted_ips'"
echo "   4. SSH 22: Solo IPs en 'admin_ips'"
echo "   5. Fail2ban: Protección automática"
echo "   6. Logging: Sistema completo de logs"
echo "   7. Monitoreo: Script /usr/local/bin/monitor_nftables.sh"
echo ""
echo "⚠️  ACCIONES REQUERIDAS:"
echo "   1. Edita /etc/nftables.conf y CAMBIA:"
echo "      - '192.168.1.0/24' por tu red real"
echo "      - Agrega IPs de tus servidores de aplicación"
echo "   2. Para aplicar cambios: sudo nft -f /etc/nftables.conf"
echo ""
echo "🔧 COMANDOS ÚTILES:"
echo "   Ver reglas: sudo nft list ruleset"
echo "   Ver IPs bloqueadas: sudo fail2ban-client status"
echo "   Monitor en tiempo real: sudo nft monitor trace"
echo "   Logs: sudo tail -f /var/log/nftables/nftables.log"
echo "   Script monitoreo: sudo /usr/local/bin/monitor_nftables.sh"
echo ""
echo "💾 BACKUPS en: $BACKUP_DIR"
echo "============================================="
