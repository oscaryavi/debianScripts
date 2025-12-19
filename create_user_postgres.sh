cat > /tmp/create_secure_users.sh << 'EOF'
#!/bin/bash
echo "=== CREACIÓN USUARIOS SEGUROS POSTGRESQL ==="
echo ""

# Variables configurables
read -sp "Contraseña para dba_admin: " DBA_PASS
echo
read -sp "Confirmar contraseña dba_admin: " DBA_PASS_CONFIRM
echo

read -sp "Contraseña para app_user: " APP_PASS
echo
read -sp "Confirmar contraseña app_user: " APP_PASS_CONFIRM
echo

read -sp "Contraseña para pgbouncer_user: " PGB_PASS
echo
read -sp "Confirmar contraseña pgbouncer_user: " PGB_PASS_CONFIRM
echo

# Verificar contraseñas
if [ "$DBA_PASS" != "$DBA_PASS_CONFIRM" ] || [ "$APP_PASS" != "$APP_PASS_CONFIRM" ] || [ "$PGB_PASS" != "$PGB_PASS_CONFIRM" ]; then
    echo "❌ Error: Las contraseñas no coinciden"
    exit 1
fi

echo "Creando usuarios..."

# Conectar y crear usuarios
sudo -u postgres psql -p 5432 << SQL
-- ============================================
-- 1. USUARIO PARA ADMINISTRACIÓN REMOTA (dba_admin)
-- ============================================
CREATE USER dba_admin WITH 
    PASSWORD '$DBA_PASS'
    NOSUPERUSER
    CREATEDB
    CREATEROLE
    NOINHERIT
    LOGIN
    CONNECTION LIMIT 5
    VALID UNTIL 'infinity';

COMMENT ON ROLE dba_admin IS 'Administrador de base de datos - Acceso remoto seguro';

-- ============================================
-- 2. USUARIO PARA APLICACIÓN APACHE (app_user)
-- ============================================
CREATE USER app_user WITH 
    PASSWORD '$APP_PASS'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT
    LOGIN
    CONNECTION LIMIT 50
    VALID UNTIL 'infinity';

COMMENT ON ROLE app_user IS 'Usuario para aplicación Apache - Privilegios mínimos';

-- ============================================
-- 3. USUARIO PARA PGBOUNCER (pgbouncer_user)
-- ============================================
CREATE USER pgbouncer_user WITH 
    PASSWORD '$PGB_PASS'
    NOSUPERUSER
    NOCREATEDB
    NOCREATEROLE
    NOINHERIT
    LOGIN
    CONNECTION LIMIT 10
    VALID UNTIL 'infinity';

COMMENT ON ROLE pgbouncer_user IS 'Usuario para conexiones PgBouncer';

-- ============================================
-- 4. CREAR DATABASE PARA LA APLICACIÓN
-- ============================================
CREATE DATABASE app_db 
    OWNER = app_user
    ENCODING = 'UTF8'
    LC_COLLATE = 'en_US.UTF-8'
    LC_CTYPE = 'en_US.UTF-8'
    TEMPLATE = template0
    CONNECTION LIMIT = 100;

COMMENT ON DATABASE app_db IS 'Base de datos principal para la aplicación';

-- ============================================
-- 5. CONFIGURAR PRIVILEGIOS
-- ============================================
-- Dar acceso dba_admin a todas las bases (como admin)
GRANT ALL PRIVILEGES ON DATABASE app_db TO dba_admin;
GRANT CREATE ON DATABASE app_db TO dba_admin;

-- app_user es dueño de app_db (ya está configurado por CREATE DATABASE)
-- Otros privilegios específicos:
GRANT CONNECT ON DATABASE app_db TO app_user;
GRANT CONNECT ON DATABASE postgres TO pgbouncer_user;

-- Para monitoreo (opcional)
GRANT pg_monitor TO dba_admin;

-- ============================================
-- 6. VERIFICAR
-- ============================================
\du+
\l+
SQL

echo "✅ Usuarios creados exitosamente"
echo ""
EOF
