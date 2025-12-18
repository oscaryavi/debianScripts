#!/bin/bash
echo "=== CONFIGURACIÓN NFTABLES PARA POSTGRESQL ==="
echo ""

# 1. Backup de configuración actual
echo "1. Haciendo backup de configuración actual..."
sudo cp /etc/nftables.conf /etc/nftables.conf.backup.$(date +%Y%m%d_%H%M%S)
echo "✅ Backup creado"
echo ""

# 2. Crear configuración principal
echo "2. Creando configuración principal..."
cat > /tmp/nftables_main.conf << 'NFT_MAIN'
#!/usr/sbin/nft -f
flush ruleset

table inet filter {
    # IPs permitidas para PgBouncer (¡AJUSTA ESTAS IPs!)
    set allowed_pgbouncer_clients {
        type ipv4_addr
        flags interval
        elements = {
            127.0.0.1,           # localhost
            192.168.1.100,       # Tu servidor de aplicaciones 1
            192.168.1.101,       # Tu servidor de aplicaciones 2
            # Agrega más IPs según necesites
        }
    }

    chain input {
        type filter hook input priority 0; policy drop;

        # Conexiones establecidas
        ct state established,related accept

        # Loopback
        iif "lo" accept

        # ICMP (ping limitado)
        ip protocol icmp icmp type { echo-request } limit rate 5/second accept

        # SSH (solo desde IPs específicas si está en Internet)
        tcp dport 22 ip saddr @allowed_pgbouncer_clients accept

        # PgBouncer (6432) - solo desde IPs autorizadas
        tcp dport 6432 ip saddr @allowed_pgbouncer_clients accept

        # PostgreSQL (5432) - SOLO localhost
        tcp dport 5432 ip saddr 127.0.0.1 accept

        # Logging de intentos bloqueados
        tcp dport {5432, 6432} log prefix "BLOCKED-DB-ACCESS: " drop
    }

    chain forward {
        type filter hook forward priority 0; policy drop;
    }

    chain output {
        type filter hook output priority 0; policy accept;
    }
}
NFT_MAIN

sudo cp /tmp/nftables_main.conf /etc/nftables.conf
echo "✅ Configuración principal creada"
echo ""

# 3. Crear configuración de monitoreo
echo "3. Configurando monitoreo..."
cat > /tmp/nftables_monitor.nft << 'NFT_MONITOR'
table inet monitor {
    chain log_postgres {
        type filter hook input priority -100;
        
        # Log detallado de acceso a bases de datos
        tcp dport 5432 log prefix "DIRECT-POSTGRES: " group 0
        tcp dport 6432 log prefix "PGBOUNCER-ACCESS: " group 0
        
        # Contar conexiones por IP
        tcp dport 6432 ct state new {
            # Puedes agregar aquí reglas de rate limiting
        }
    }
}
NFT_MONITOR

sudo cp /tmp/nftables_monitor.nft /etc/nftables.d/monitor.nft
echo "✅ Configuración de monitoreo creada"
echo ""

# 4. Aplicar configuración
echo "4. Aplicando configuración..."
sudo nft -f /etc/nftables.conf
sudo nft -f /etc/nftables.d/monitor.nft 2>/dev/null || true

# 5. Hacer persistente
echo "5. Haciendo configuración persistente..."
sudo nft list ruleset > /etc/nftables.conf
sudo systemctl restart nftables
echo ""

# 6. Verificar
echo "6. Verificando configuración..."
sudo nft list ruleset | grep -A5 -B5 "5432\|6432"
echo ""

# 7. Probar conectividad
echo "7. Probando conectividad..."
echo "Desde localhost a PostgreSQL (debe funcionar):"
sudo -u postgres pg_isready -p 5432
echo ""
echo "Desde localhost a PgBouncer (debe funcionar):"
sudo -u postgres pg_isready -h 127.0.0.1 -p 6432
echo ""
echo "Desde otra IP (debe fallar - prueba manual necesaria):"
echo "Comando: pg_isready -h [IP_SERVIDOR] -p 6432"
echo ""

echo "=== CONFIGURACIÓN COMPLETADA ==="
echo ""
echo "📋 RESUMEN DE REGLAS APLICADAS:"
echo "1. PostgreSQL (5432): Solo localhost"
echo "2. PgBouncer (6432): Solo IPs en conjunto 'allowed_pgbouncer_clients'"
echo "3. Logging: Todos los intentos bloqueados se registran"
echo "4. Política por defecto: DROP (rechazar todo lo no permitido)"
echo ""
echo "⚠️  IMPORTANTE: Edita /etc/nftables.conf para agregar tus IPs reales"
echo "   Busca 'allowed_pgbouncer_clients' y agrega las IPs de tus aplicaciones"
