#!/bin/bash
echo "=== INSTALANDO pg_stat_statements (EXTENSIÓN ESENCIAL) ==="
echo ""

# 1. Backup de configuración
BACKUP_FILE="/etc/postgresql/17/main/postgresql.conf.backup_$(date +%s)"
sudo cp /etc/postgresql/17/main/postgresql.conf "$BACKUP_FILE"
echo "✅ Backup creado: $BACKUP_FILE"
echo ""

# 2. Verificar paquete instalado
echo "2. Verificando paquete..."
if dpkg -l | grep -q "postgresql-17-pg-stat-statements"; then
    echo "   ✅ Paquete ya instalado"
else
    echo "   📦 Instalando paquete..."
    sudo apt update
    sudo apt install -y postgresql-17-pg-stat-statements
fi
echo ""

# 3. Configurar postgresql.conf
echo "3. Configurando postgresql.conf..."

# Eliminar configuraciones previas si existen
sudo sed -i '/^shared_preload_libraries/d' /etc/postgresql/17/main/postgresql.conf
sudo sed -i '/^pg_stat_statements\./d' /etc/postgresql/17/main/postgresql.conf

# Agregar configuración nueva
cat >> /etc/postgresql/17/main/postgresql.conf << 'CONFIG'

# ========= PG_STAT_STATEMENTS =========
# Extensión para monitoreo de queries - ESENCIAL para producción
shared_preload_libraries = 'pg_stat_statements'

# Configuración de pg_stat_statements
pg_stat_statements.max = 10000          # Máximo de queries trackeadas
pg_stat_statements.track = all          # Trackear todas las queries
pg_stat_statements.track_utility = on   # Trackear comandos como VACUUM
pg_stat_statements.save = on            # Guardar estadísticas entre reinicios
CONFIG

echo "   ✅ Configuración agregada"
echo ""

# 4. Reiniciar PostgreSQL
echo "4. Reiniciando PostgreSQL..."
sudo systemctl restart postgresql@17-main
sleep 3
echo ""

# 5. Verificar carga
echo "5. Verificando carga de librería..."
LOAD_RESULT=$(sudo -u postgres psql -p 5432 -t -c "SHOW shared_preload_libraries;" 2>/dev/null)
if echo "$LOAD_RESULT" | grep -q "pg_stat_statements"; then
    echo "   ✅ pg_stat_statements cargado en shared_preload_libraries"
else
    echo "   ❌ No se cargó. Verificando logs..."
    sudo journalctl -u postgresql@17-main -n 5 --no-pager
fi
echo ""

# 6. Crear extensión en bases de datos
echo "6. Creando extensión en bases de datos..."
for db in $(sudo -u postgres psql -p 5432 -t -c "SELECT datname FROM pg_database WHERE datname NOT IN ('template0');"); do
    db=$(echo $db | xargs)  # Trim whitespace
    echo "   Creando en: $db"
    sudo -u postgres psql -p 5432 -d "$db" -c "CREATE EXTENSION IF NOT EXISTS pg_stat_statements;" 2>/dev/null
done
echo ""

# 7. Verificar funcionamiento
echo "7. Verificando funcionamiento..."
sudo -u postgres psql -p 5432 -c "
SELECT 
    'Extension installed: ' || 
    CASE WHEN EXISTS (
        SELECT 1 FROM pg_extension WHERE extname = 'pg_stat_statements'
    ) THEN '✅' ELSE '❌' END as status;
    
SELECT query, calls, total_exec_time, mean_exec_time
FROM pg_stat_statements 
ORDER BY total_exec_time DESC 
LIMIT 3;
" 2>/dev/null || echo "   Aún no hay datos de queries"

echo ""
echo "=== INSTALACIÓN COMPLETADA ==="
echo "La extensión pg_stat_statements está lista para usar."
echo "Consulta las queries más lentas con:"
echo "  sudo -u postgres psql -p 5432 -c \"SELECT query, calls, total_exec_time FROM pg_stat_statements ORDER BY total_exec_time DESC LIMIT 10;\""
EOF
