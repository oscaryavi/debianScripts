#!/bin/bash
# validate_postgres_config.sh

echo "==============================================="
echo "VALIDACIÓN COMPLETA CONFIGURACIÓN POSTGRESQL"
echo "Para 20GB RAM - $(date)"
echo "==============================================="

# Configuración esperada para 20GB RAM
declare -A EXPECTED_SETTINGS=(
    ["shared_buffers"]="4GB"
    ["work_mem"]="4MB"
    ["max_connections"]="200"
    ["effective_cache_size"]="15GB"
    ["maintenance_work_mem"]="1GB"
    ["wal_buffers"]="32MB"
    ["checkpoint_completion_target"]="0.8"
    ["random_page_cost"]="1.1"
)

# 1. Verificar archivo de configuración
echo "1. ARCHIVO DE CONFIGURACIÓN:"
CONFIG_FILE="/etc/postgresql/17/main/postgresql.conf"
if [ -f "$CONFIG_FILE" ]; then
    echo "   ✅ Archivo encontrado: $CONFIG_FILE"
    echo "   Tamaño: $(ls -lh $CONFIG_FILE | awk '{print $5}')"
    
    # Contar configuraciones no comentadas
    ACTIVE_SETTINGS=$(grep -c "^[a-z]" $CONFIG_FILE)
    COMMENTED_SETTINGS=$(grep -c "^#" $CONFIG_FILE)
    echo "   Configuraciones activas: $ACTIVE_SETTINGS"
    echo "   Configuraciones comentadas: $COMMENTED_SETTINGS"
else
    echo "   ❌ Archivo NO encontrado!"
fi

echo -e "\n2. CONFIGURACIONES CARGADAS vs ESPERADAS:"

# Obtener configuraciones actuales
for SETTING in "${!EXPECTED_SETTINGS[@]}"; do
    ACTUAL_VALUE=$(sudo -u postgres psql -p 5432 -t -c "SELECT setting FROM pg_settings WHERE name = '$SETTING';" 2>/dev/null | xargs)
    EXPECTED_VALUE="${EXPECTED_SETTINGS[$SETTING]}"
    
    if [ -n "$ACTUAL_VALUE" ]; then
        # Convertir a bytes para comparación
        ACTUAL_BYTES=$(echo $ACTUAL_VALUE | awk '
            /GB/{printf "%.0f", $1*1024*1024*1024; next}
            /MB/{printf "%.0f", $1*1024*1024; next}
            /kB/{printf "%.0f", $1*1024; next}
            {printf "%.0f", $1}
        ')
        
        EXPECTED_BYTES=$(echo $EXPECTED_VALUE | awk '
            /GB/{printf "%.0f", $1*1024*1024*1024; next}
            /MB/{printf "%.0f", $1*1024*1024; next}
            /kB/{printf "%.0f", $1*1024; next}
            {printf "%.0f", $1}
        ')
        
        # Calcular diferencia
        DIFF_PERCENT=$(( (ACTUAL_BYTES - EXPECTED_BYTES) * 100 / EXPECTED_BYTES ))
        
        if [ $DIFF_PERCENT -ge -10 ] && [ $DIFF_PERCENT -le 10 ]; then
            echo "   ✅ $SETTING: $ACTUAL_VALUE (esperado: $EXPECTED_VALUE)"
        else
            echo "   ⚠️  $SETTING: $ACTUAL_VALUE (esperado: $EXPECTED_VALUE) - Diferencia: $DIFF_PERCENT%"
        fi
    else
        echo "   ❌ $SETTING: NO CONFIGURADO"
    fi
done

echo -e "\n3. USO DE MEMORIA DEL SISTEMA:"
TOTAL_RAM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
TOTAL_RAM_GB=$((TOTAL_RAM_KB / 1024 / 1024))
echo "   RAM Total: ${TOTAL_RAM_GB}GB"

# Calcular memoria PostgreSQL
PG_MEMORY_KB=$(ps aux | grep postgres | grep -v grep | awk '{sum += $6} END {print sum}')
PG_MEMORY_GB=$(echo "scale=2; $PG_MEMORY_KB / 1024 / 1024" | bc)
echo "   PostgreSQL usando: ${PG_MEMORY_GB}GB (${TOTAL_RAM_GB}GB total)"

# Porcentaje de uso
USAGE_PERCENT=$(echo "scale=1; ($PG_MEMORY_KB * 100) / ($TOTAL_RAM_KB * 1024)" | bc)
if [ $(echo "$USAGE_PERCENT < 70" | bc) -eq 1 ]; then
    echo "   ✅ Uso de RAM: ${USAGE_PERCENT}% (óptimo < 70%)"
elif [ $(echo "$USAGE_PERCENT < 85" | bc) -eq 1 ]; then
    echo "   ⚠️  Uso de RAM: ${USAGE_PERCENT}% (alto < 85%)"
else
    echo "   ❌ Uso de RAM: ${USAGE_PERCENT}% (crítico > 85%)"
fi

echo -e "\n4. ESTADO DE CONEXIONES:"
CONN_INFO=$(sudo -u postgres psql -p 5432 -t -c "
SELECT 
    'Total: ' || count(*) || ', ' ||
    'Active: ' || sum(CASE WHEN state = 'active' THEN 1 ELSE 0 END) || ', ' ||
    'Idle: ' || sum(CASE WHEN state = 'idle' THEN 1 ELSE 0 END) || ', ' ||
    'Idle in TX: ' || sum(CASE WHEN state = 'idle in transaction' THEN 1 ELSE 0 END)
FROM pg_stat_activity 
WHERE pid <> pg_backend_pid();
" 2>/dev/null)
echo "   $CONN_INFO"

MAX_CONN=$(sudo -u postgres psql -p 5432 -t -c "SELECT setting FROM pg_settings WHERE name = 'max_connections';" 2>/dev/null | xargs)
CURRENT_CONN=$(sudo -u postgres psql -p 5432 -t -c "SELECT count(*) FROM pg_stat_activity WHERE pid <> pg_backend_pid();" 2>/dev/null | xargs)
CONN_PERCENT=$((CURRENT_CONN * 100 / MAX_CONN))

if [ $CONN_PERCENT -lt 60 ]; then
    echo "   ✅ Conexiones: $CURRENT_CONN/$MAX_CONN (${CONN_PERCENT}%)"
elif [ $CONN_PERCENT -lt 80 ]; then
    echo "   ⚠️  Conexiones: $CURRENT_CONN/$MAX_CONN (${CONN_PERCENT}%) - Considera aumentar"
else
    echo "   ❌ Conexiones: $CURRENT_CONN/$MAX_CONN (${CONN_PERCENT}%) - Muy alto!"
fi

echo -e "\n5. CHECKPOINTS Y WAL:"
sudo -u postgres psql -p 5432 -t -c "
SELECT 
    'Checkpoints: ' || checkpoints_timed || ' timed, ' || 
    checkpoints_req || ' requested, ' ||
    'Buffer checkpoint rate: ' || ROUND(buffer_checkpoint::numeric / (1024*1024), 2) || ' MB/s',
    'WAL: ' || ROUND(wal_size::numeric / (1024*1024*1024), 2) || ' GB total'
FROM (
    SELECT 
        (SELECT setting FROM pg_stat_file('pg_wal') as (size bigint, modification timestamp)) as wal_size,
        (SELECT checkpoints_timed FROM pg_stat_bgwriter) as checkpoints_timed,
        (SELECT checkpoints_req FROM pg_stat_bgwriter) as checkpoints_req,
        (SELECT buffers_checkpoint FROM pg_stat_bgwriter) * 8192 / 
        (SELECT EXTRACT(EPOCH FROM (now() - stats_reset)) FROM pg_stat_bgwriter) as buffer_checkpoint
) stats;
" 2>/dev/null

echo -e "\n6. RENDIMIENTO DISCO I/O:"
sudo -u postgres psql -p 5432 -t -c "
SELECT 
    'Heap hits: ' || ROUND(heap_blks_hit * 100.0 / NULLIF(heap_blks_hit + heap_blks_read, 0), 2) || '%',
    'Idx hits: ' || ROUND(idx_blks_hit * 100.0 / NULLIF(idx_blks_hit + idx_blks_read, 0), 2) || '%',
    'TOAST hits: ' || ROUND(toast_blks_hit * 100.0 / NULLIF(toast_blks_hit + toast_blks_read, 0), 2) || '%'
FROM pg_statio_user_tables 
WHERE relname = 'pgbench_accounts' OR schemaname = 'public' LIMIT 1;
" 2>/dev/null || echo "   (Ejecuta pgbench primero para tener datos)"

echo -e "\n==============================================="
echo "RECOMENDACIONES FINALES:"
echo "==============================================="

# Generar recomendaciones basadas en análisis
if [ $(echo "$USAGE_PERCENT > 80" | bc) -eq 1 ]; then
    echo "⚠️  RECOMENDACIÓN: Reducir shared_buffers o work_mem"
fi

if [ $CONN_PERCENT -gt 70 ]; then
    echo "⚠️  RECOMENDACIÓN: Considera usar PgBouncer para más conexiones"
fi

# Verificar si PgBouncer está instalado
if systemctl is-active --quiet pgbouncer; then
    echo "✅ PgBouncer está activo"
else
    echo "⚠️  RECOMENDACIÓN: Instala PgBouncer para manejar 1000+ usuarios"
fi

echo -e "\nPara test de carga real ejecuta:"
echo "pgbench -p 5432 -i -s 100 testdb && pgbench -p 5432 -c 50 -j 4 -T 300 testdb"
