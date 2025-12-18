#!/bin/bash
# Validador de configuración PostgreSQL 17
# Verifica que todos los parámetros sean válidos para PG17

PG_VERSION="17"
CONFIG_FILE="/etc/postgresql/$PG_VERSION/main/postgresql.conf"
LOG_FILE="/var/log/pg_config_validation.log"

echo "=== VALIDACIÓN CONFIGURACIÓN POSTGRESQL $PG_VERSION ===" | tee -a "$LOG_FILE"
echo "Fecha: $(date)" | tee -a "$LOG_FILE"

# 1. Obtener parámetros válidos de PostgreSQL 17
echo "Obteniendo parámetros válidos para PostgreSQL $PG_VERSION..." | tee -a "$LOG_FILE"
VALID_PARAMS=$(sudo -u postgres psql -p 5432 -t -c "SELECT name FROM pg_settings ORDER BY name;" 2>/dev/null)

if [ -z "$VALID_PARAMS" ]; then
    echo "ERROR-nuevo: No se puede conectar a PostgreSQL $PG_VERSION" | tee -a "$LOG_FILE"
    exit 1
fi

# 2. Leer configuración actual
echo "Analizando: $CONFIG_FILE" | tee -a "$LOG_FILE"
CONFIG_PARAMS=$(grep -E "^\s*[a-z_]" "$CONFIG_FILE" | grep -v "^#" | awk -F= '{print $1}' | sed 's/ //g')

# 3. Validar cada parámetro
INVALID_COUNT=0
echo "" | tee -a "$LOG_FILE"
echo "PARÁMETROS INVÁLIDOS/PROBLEMÁTICOS:" | tee -a "$LOG_FILE"

for param in $CONFIG_PARAMS; do
    # Verificar si existe en PostgreSQL 17
    if ! echo "$VALID_PARAMS" | grep -q "^$param$"; then
        echo "  ❌ $param - NO VÁLIDO en PostgreSQL $PG_VERSION" | tee -a "$LOG_FILE"
        INVALID_COUNT=$((INVALID_COUNT + 1))
        
        # Sugerir alternativas para parámetros obsoletos comunes
        case $param in
            "stats_temp_directory")
                echo "     ⚠️  Obsoleto desde PG 9.4. Estadísticas se manejan en memoria."
                ;;
            "checkpoint_segments")
                echo "     ⚠️  Reemplazado por max_wal_size en PG 9.5+"
                ;;
            "wal_keep_segments")
                echo "     ⚠️  Reemplazado por wal_keep_size en PG 13+"
                ;;
        esac
    fi
done

# 4. Resultado
echo "" | tee -a "$LOG_FILE"
if [ $INVALID_COUNT -eq 0 ]; then
    echo "✅ CONFIGURACIÓN 100% VÁLIDA para PostgreSQL $PG_VERSION" | tee -a "$LOG_FILE"
else
    echo "⚠️  ENCONTRADOS $INVALID_COUNT parámetros inválidos" | tee -a "$LOG_FILE"
    echo "Revisa: $LOG_FILE para detalles" | tee -a "$LOG_FILE"
fi

echo "Parámetros válidos totales en PG$PG_VERSION: $(echo "$VALID_PARAMS" | wc -l)" | tee -a "$LOG_FILE"
VALIDATE
