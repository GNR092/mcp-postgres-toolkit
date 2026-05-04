import os
import re
from typing import Any, Dict, Optional

import psycopg2
from fastmcp import FastMCP
from psycopg2.extras import RealDictCursor
from psycopg2 import sql

app = FastMCP("mcp-postgres-toolkit")
ACTIVE_DATABASE: Optional[str] = None
MAX_DEFAULT_ROWS = 200
RUNTIME_CONN_CONFIG: Dict[str, str] = {}
SENSITIVE_COLUMN_PATTERNS = [
    r"password",
    r"contrasena",
    r"token",
    r"secret",
    r"api[_-]?key",
    r"firma",
]
DANGEROUS_SQL_PATTERNS = [
    r"\bdrop\b",
    r"\balter\b",
    r"\btruncate\b",
    r"\binsert\b",
    r"\bupdate\b",
    r"\bdelete\b",
    r"\bgrant\b",
    r"\brevoke\b",
    r"\bcreate\b",
    r"\bcomment\b",
]


def _env(*keys: str, default: Optional[str] = None) -> Optional[str]:
    """Retorna el primer valor de entorno no vacio encontrado."""
    for key in keys:
        value = os.environ.get(key)
        if value:
            return value
    return default


def _cfg(primary_key: str, *env_keys: str, default: Optional[str] = None) -> Optional[str]:
    """Retorna valor de configuracion en runtime o variables de entorno."""
    runtime_value = RUNTIME_CONN_CONFIG.get(primary_key)
    if runtime_value:
        return runtime_value
    return _env(*env_keys, default=default)


def _is_sensitive_column(column_name: str) -> bool:
    """Indica si el nombre de columna coincide con un patron sensible."""
    normalized = column_name.strip().lower()
    return any(re.search(pattern, normalized) for pattern in SENSITIVE_COLUMN_PATTERNS)


def _mask_sensitive_rows(rows: list[Dict[str, Any]], mask: str = "***") -> list[Dict[str, Any]]:
    """Enmascara campos sensibles en un conjunto de filas."""
    masked_rows: list[Dict[str, Any]] = []
    for row in rows:
        masked_row: Dict[str, Any] = {}
        for key, value in row.items():
            if _is_sensitive_column(key) and value is not None:
                masked_row[key] = mask
            else:
                masked_row[key] = value
        masked_rows.append(masked_row)
    return masked_rows


def _validate_single_statement(query: str) -> None:
    """Valida que la consulta sea una sola sentencia SQL."""
    normalized = query.strip().rstrip(";")
    if ";" in normalized:
        raise ValueError("Solo se permite una sentencia SQL por consulta.")


def _validate_read_only_sql(query: str) -> None:
    """Valida que la consulta sea de solo lectura y sin keywords peligrosas."""
    normalized = query.strip().lower()
    if not (normalized.startswith("select") or normalized.startswith("with")):
        raise ValueError("Solo se permiten consultas de lectura (SELECT/WITH).")

    if any(re.search(pattern, normalized) for pattern in DANGEROUS_SQL_PATTERNS):
        raise ValueError("La consulta contiene keywords bloqueadas por seguridad.")

    _validate_single_statement(query)


def get_db_connection(database: Optional[str] = None):
    """
    Crea y retorna una conexion a PostgreSQL.

    Args:
        database: Nombre de base de datos a usar. Si no se envia, usa la base activa
            definida con `connect_database`; si no existe, usa `DB_NAME`.

    Returns:
        Conexion psycopg2 con cursor tipo diccionario.

    Raises:
        ValueError: Si no se pudo resolver el nombre de base de datos.
    """
    db_name = database or ACTIVE_DATABASE or _env("DB_NAME", "PGDATABASE")

    if not db_name:
        raise ValueError("No se encontro el nombre de base de datos. Define DB_NAME o envia 'database'.")

    conn = psycopg2.connect(
        host=_cfg("host", "DB_HOST", "PGHOST", default="localhost"),
        database=db_name,
        user=_cfg("user", "DB_USER", "PGUSER"),
        password=_cfg("password", "DB_PASS", "PGPASSWORD"),
        port=_cfg("port", "DB_PORT", "PGPORT", default="5432"),
        cursor_factory=RealDictCursor,
    )
    return conn


def _resolve_database(database: Optional[str] = None) -> str:
    """
    Resuelve que base de datos se debe usar en la operacion.

    Orden de prioridad: argumento `database`, base activa, variable `DB_NAME`.
    """
    db_name = (
        database
        or ACTIVE_DATABASE
        or RUNTIME_CONN_CONFIG.get("default_database")
        or _env("DB_NAME", "PGDATABASE")
    )
    if not db_name:
        raise ValueError("No se encontro base de datos activa. Usa connect_database o define DB_NAME.")
    return db_name


@app.tool
def list_databases() -> Dict[str, Any]:
    """
    Lista las bases de datos no plantilla disponibles en el servidor PostgreSQL.

    Returns:
        Diccionario con la llave `databases` y un arreglo de nombres.
    """
    conn = get_db_connection(database="postgres")
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT datname
                FROM pg_database
                WHERE datistemplate = false
                ORDER BY datname;
                """
            )
            rows = cur.fetchall()
        dbs = [row["datname"] for row in rows]
        return {"databases": dbs, "active_database": ACTIVE_DATABASE}
    finally:
        conn.close()


@app.tool
def get_active_database() -> Dict[str, Any]:
    """
    Retorna la base de datos activa en memoria del proceso.

    Returns:
        Diccionario con `active_database`.
    """
    return {"active_database": ACTIVE_DATABASE or _env("DB_NAME", "PGDATABASE")}


@app.tool
def set_connection_config(
    host: str,
    user: str,
    password: str,
    port: str = "5432",
    default_database: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Define credenciales de conexion en memoria del proceso MCP.

    Evita depender de variables de entorno en el cliente. La configuracion
    vive mientras el proceso del servidor este encendido.

    Args:
        host: Host de PostgreSQL.
        user: Usuario de PostgreSQL.
        password: Contrasena del usuario.
        port: Puerto de PostgreSQL.
        default_database: Base por defecto opcional para consultas.

    Returns:
        Configuracion activa sin exponer la contrasena.
    """
    RUNTIME_CONN_CONFIG["host"] = host
    RUNTIME_CONN_CONFIG["user"] = user
    RUNTIME_CONN_CONFIG["password"] = password
    RUNTIME_CONN_CONFIG["port"] = str(port)

    if default_database:
        RUNTIME_CONN_CONFIG["default_database"] = default_database

    return {
        "configured": True,
        "host": RUNTIME_CONN_CONFIG["host"],
        "port": RUNTIME_CONN_CONFIG["port"],
        "user": RUNTIME_CONN_CONFIG["user"],
        "default_database": RUNTIME_CONN_CONFIG.get("default_database"),
    }


@app.tool
def get_connection_config_status() -> Dict[str, Any]:
    """
    Muestra el estado de configuracion sin revelar secretos.

    Returns:
        Estado de configuracion de host, puerto, usuario y password.
    """
    return {
        "host": _cfg("host", "DB_HOST", "PGHOST", default="localhost"),
        "port": _cfg("port", "DB_PORT", "PGPORT", default="5432"),
        "user": _cfg("user", "DB_USER", "PGUSER"),
        "password_configured": bool(_cfg("password", "DB_PASS", "PGPASSWORD")),
        "database_resolved": ACTIVE_DATABASE
        or RUNTIME_CONN_CONFIG.get("default_database")
        or _env("DB_NAME", "PGDATABASE"),
    }


@app.tool
def run_query(query: str, database: Optional[str] = None) -> Dict[str, Any]:
    """
    Ejecuta una consulta SQL de solo lectura (SELECT).

    Args:
        query: Sentencia SQL a ejecutar (solo SELECT).
        database: Base de datos destino. Si no se envia, usa la base activa o `DB_NAME`.

    Returns:
        Diccionario con `database` utilizada y `rows` con el resultado.

    Raises:
        ValueError: Si la consulta no inicia con SELECT.
    """
    _validate_read_only_sql(query)

    target_database = _resolve_database(database)
    conn = get_db_connection(database=target_database)
    try:
        with conn.cursor() as cur:
            cur.execute(query)
            rows = cur.fetchall()
            limited_rows = rows[:MAX_DEFAULT_ROWS]
            masked_rows = _mask_sensitive_rows(limited_rows)
        return {
            "database": target_database,
            "row_count": len(rows),
            "rows": masked_rows,
            "rows_limited": len(rows) > MAX_DEFAULT_ROWS,
            "masked_sensitive_fields": True,
        }
    finally:
        conn.close()


@app.tool
def run_query_safe(
    query: str,
    params: Optional[list[Any]] = None,
    database: Optional[str] = None,
    timeout_ms: int = 15000,
) -> Dict[str, Any]:
    """
    Ejecuta una consulta parametrizada de solo lectura con timeout.

    Args:
        query: Consulta SQL SELECT/WITH.
        params: Parametros para placeholders (%s).
        database: Base destino opcional.
        timeout_ms: Timeout por consulta en milisegundos.

    Returns:
        Diccionario con filas, metadatos y estado de enmascarado.
    """
    _validate_read_only_sql(query)
    target_database = _resolve_database(database)
    safe_timeout = max(1000, min(timeout_ms, 120000))

    conn = get_db_connection(database=target_database)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SET LOCAL statement_timeout = %s", (safe_timeout,))
                cur.execute(query, params or [])
                rows = cur.fetchall()
                limited_rows = rows[:MAX_DEFAULT_ROWS]
                masked_rows = _mask_sensitive_rows(limited_rows)

        return {
            "database": target_database,
            "timeout_ms": safe_timeout,
            "row_count": len(rows),
            "rows": masked_rows,
            "rows_limited": len(rows) > MAX_DEFAULT_ROWS,
            "masked_sensitive_fields": True,
        }
    finally:
        conn.close()


@app.tool
def connect_database(database: str) -> Dict[str, Any]:
    """
    Define una base de datos activa para futuras consultas.

    Esta funcion valida la conexion a la base solicitada antes de guardarla
    como activa en memoria del proceso MCP.

    Args:
        database: Nombre de la base de datos a activar.

    Returns:
        Diccionario con `active_database` y `connected`.

    Raises:
        psycopg2.Error: Si no se puede conectar a la base indicada.
    """
    global ACTIVE_DATABASE

    available = list_databases()["databases"]
    if database not in available:
        raise ValueError(f"La base '{database}' no existe o no es accesible. Disponibles: {available}")

    conn = get_db_connection(database=database)
    try:
        with conn.cursor() as cur:
            cur.execute("SELECT 1 AS ok;")
            cur.fetchone()
    finally:
        conn.close()

    ACTIVE_DATABASE = database
    return {"active_database": ACTIVE_DATABASE, "connected": True}


@app.tool
def list_tables(schema: str = "public", database: Optional[str] = None) -> Dict[str, Any]:
    """
    Lista tablas de un esquema en la base seleccionada.

    Args:
        schema: Esquema a consultar (por defecto `public`).
        database: Base destino opcional.

    Returns:
        Diccionario con `database`, `schema` y `tables`.
    """
    target_database = _resolve_database(database)
    conn = get_db_connection(database=target_database)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = %s
                  AND table_type = 'BASE TABLE'
                ORDER BY table_name;
                """,
                (schema,),
            )
            rows = cur.fetchall()
        return {
            "database": target_database,
            "schema": schema,
            "tables": [row["table_name"] for row in rows],
        }
    finally:
        conn.close()


@app.tool
def list_schemas(database: Optional[str] = None) -> Dict[str, Any]:
    """
    Lista esquemas disponibles excluyendo internos de PostgreSQL.
    """
    target_database = _resolve_database(database)
    conn = get_db_connection(database=target_database)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT schema_name
                FROM information_schema.schemata
                WHERE schema_name NOT IN ('information_schema')
                  AND schema_name NOT LIKE 'pg_%'
                ORDER BY schema_name;
                """
            )
            rows = cur.fetchall()

        return {
            "database": target_database,
            "schemas": [row["schema_name"] for row in rows],
        }
    finally:
        conn.close()


@app.tool
def describe_foreign_keys(
    table_name: str,
    schema: str = "public",
    database: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Lista llaves foraneas de una tabla y su referencia.
    """
    target_database = _resolve_database(database)
    conn = get_db_connection(database=target_database)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    tc.constraint_name,
                    kcu.column_name,
                    ccu.table_schema AS foreign_table_schema,
                    ccu.table_name AS foreign_table_name,
                    ccu.column_name AS foreign_column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                 AND tc.table_schema = kcu.table_schema
                JOIN information_schema.constraint_column_usage ccu
                  ON ccu.constraint_name = tc.constraint_name
                 AND ccu.table_schema = tc.table_schema
                WHERE tc.constraint_type = 'FOREIGN KEY'
                  AND tc.table_schema = %s
                  AND tc.table_name = %s
                ORDER BY tc.constraint_name, kcu.ordinal_position;
                """,
                (schema, table_name),
            )
            rows = cur.fetchall()

        return {
            "database": target_database,
            "schema": schema,
            "table": table_name,
            "foreign_keys": rows,
            "foreign_key_count": len(rows),
        }
    finally:
        conn.close()


@app.tool
def describe_table(table_name: str, schema: str = "public", database: Optional[str] = None) -> Dict[str, Any]:
    """
    Describe columnas y metadatos de una tabla.

    Args:
        table_name: Nombre de la tabla.
        schema: Esquema donde se encuentra la tabla.
        database: Base destino opcional.

    Returns:
        Diccionario con columnas, llaves primarias y total de columnas.
    """
    target_database = _resolve_database(database)
    conn = get_db_connection(database=target_database)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT
                    c.column_name,
                    c.data_type,
                    c.is_nullable,
                    c.column_default,
                    c.character_maximum_length,
                    c.numeric_precision,
                    c.numeric_scale,
                    c.ordinal_position
                FROM information_schema.columns c
                WHERE c.table_schema = %s
                  AND c.table_name = %s
                ORDER BY c.ordinal_position;
                """,
                (schema, table_name),
            )
            columns = cur.fetchall()

            if not columns:
                raise ValueError(f"La tabla '{schema}.{table_name}' no existe o no es accesible.")

            cur.execute(
                """
                SELECT kcu.column_name
                FROM information_schema.table_constraints tc
                JOIN information_schema.key_column_usage kcu
                  ON tc.constraint_name = kcu.constraint_name
                 AND tc.table_schema = kcu.table_schema
                WHERE tc.constraint_type = 'PRIMARY KEY'
                  AND tc.table_schema = %s
                  AND tc.table_name = %s
                ORDER BY kcu.ordinal_position;
                """,
                (schema, table_name),
            )
            pk_rows = cur.fetchall()
            primary_keys = [row["column_name"] for row in pk_rows]

        return {
            "database": target_database,
            "schema": schema,
            "table": table_name,
            "primary_keys": primary_keys,
            "column_count": len(columns),
            "columns": columns,
        }
    finally:
        conn.close()


@app.tool
def sample_table(
    table_name: str,
    schema: str = "public",
    limit: int = 20,
    database: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Obtiene una muestra de filas de una tabla sin escribir SQL manual.

    Args:
        table_name: Nombre de tabla.
        schema: Esquema de la tabla.
        limit: Numero de filas a retornar (maximo 200).
        database: Base destino opcional.

    Returns:
        Diccionario con filas de muestra y metadatos basicos.
    """
    target_database = _resolve_database(database)
    safe_limit = max(1, min(limit, MAX_DEFAULT_ROWS))
    conn = get_db_connection(database=target_database)
    try:
        with conn.cursor() as cur:
            query = f'SELECT * FROM "{schema}"."{table_name}" LIMIT %s'
            cur.execute(query, (safe_limit,))
            rows = cur.fetchall()
            masked_rows = _mask_sensitive_rows(rows)
        return {
            "database": target_database,
            "schema": schema,
            "table": table_name,
            "limit": safe_limit,
            "row_count": len(rows),
            "rows": masked_rows,
            "masked_sensitive_fields": True,
        }
    finally:
        conn.close()


@app.tool
def search_tables(pattern: str, schema: str = "public", database: Optional[str] = None) -> Dict[str, Any]:
    """
    Busca tablas por patron usando ILIKE.

    Args:
        pattern: Texto o patron (ej: user, %user%, cliente).
        schema: Esquema a consultar.
        database: Base destino opcional.

    Returns:
        Diccionario con coincidencias ordenadas.
    """
    target_database = _resolve_database(database)
    like_pattern = pattern if ("%" in pattern or "_" in pattern) else f"%{pattern}%"
    conn = get_db_connection(database=target_database)
    try:
        with conn.cursor() as cur:
            cur.execute(
                """
                SELECT table_name
                FROM information_schema.tables
                WHERE table_schema = %s
                  AND table_type = 'BASE TABLE'
                  AND table_name ILIKE %s
                ORDER BY table_name;
                """,
                (schema, like_pattern),
            )
            rows = cur.fetchall()
        return {
            "database": target_database,
            "schema": schema,
            "pattern": like_pattern,
            "matches": [row["table_name"] for row in rows],
        }
    finally:
        conn.close()


@app.tool
def explain_query(
    query: str,
    analyze: bool = False,
    params: Optional[list[Any]] = None,
    database: Optional[str] = None,
    timeout_ms: int = 15000,
) -> Dict[str, Any]:
    """
    Obtiene plan de ejecucion de una consulta de lectura.
    """
    _validate_read_only_sql(query)
    target_database = _resolve_database(database)
    safe_timeout = max(1000, min(timeout_ms, 120000))
    prefix = "EXPLAIN (ANALYZE, FORMAT JSON) " if analyze else "EXPLAIN (FORMAT JSON) "

    conn = get_db_connection(database=target_database)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SET LOCAL statement_timeout = %s", (safe_timeout,))
                cur.execute(prefix + query, params or [])
                plan_row = cur.fetchone()

        return {
            "database": target_database,
            "analyze": analyze,
            "timeout_ms": safe_timeout,
            "plan": plan_row["QUERY PLAN"] if plan_row else None,
        }
    finally:
        conn.close()


@app.tool
def count_rows(
    table_name: str,
    schema: str = "public",
    where: Optional[str] = None,
    params: Optional[list[Any]] = None,
    database: Optional[str] = None,
    timeout_ms: int = 15000,
) -> Dict[str, Any]:
    """
    Cuenta filas de una tabla con filtro opcional.
    """
    target_database = _resolve_database(database)
    safe_timeout = max(1000, min(timeout_ms, 120000))
    base_query = sql.SQL("SELECT COUNT(*) AS total FROM {}.{}").format(
        sql.Identifier(schema),
        sql.Identifier(table_name),
    )

    if where:
        _validate_single_statement(where)
        if any(re.search(pattern, where.lower()) for pattern in DANGEROUS_SQL_PATTERNS):
            raise ValueError("El filtro WHERE contiene keywords bloqueadas por seguridad.")
        final_query = base_query + sql.SQL(" WHERE ") + sql.SQL(where)
    else:
        final_query = base_query

    conn = get_db_connection(database=target_database)
    try:
        with conn:
            with conn.cursor() as cur:
                cur.execute("SET LOCAL statement_timeout = %s", (safe_timeout,))
                cur.execute(final_query, params or [])
                row = cur.fetchone()

        return {
            "database": target_database,
            "schema": schema,
            "table": table_name,
            "where": where,
            "total": row["total"] if row else 0,
            "timeout_ms": safe_timeout,
        }
    finally:
        conn.close()


def run() -> None:
    """Punto de entrada CLI del servidor MCP."""
    app.run()


if __name__ == "__main__":
    run()
