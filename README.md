# mcpservertools

MCP server para explorar PostgreSQL de forma dinamica y ejecutar consultas de solo lectura de manera segura.

## Caracteristicas

- Conexion dinamica en runtime sin depender de `env` en `opencode.json`.
- Listado de bases de datos disponibles.
- Seleccion de base activa para consultas subsecuentes.
- Ejecucion de `SELECT` con validacion de seguridad (solo lectura).
- Exploracion de esquemas y tablas:
  - listar tablas
  - buscar tablas por patron
  - describir estructura de tabla
  - obtener muestra de registros
- Enmascarado automatico de campos sensibles (`password`, `contrasena`, `token`, etc.).

## Requisitos

- Python 3.13+
- PostgreSQL accesible
- Dependencias:
  - `fastmcp`
  - `psycopg2`

## Instalacion

```bash
uv sync
```

## Ejecucion

```bash
mcp-postgres-toolkit
```

## Configuracion de conexion (runtime)

Primero configura la conexion desde el cliente MCP:

- `set_connection_config(host, user, password, port="5432", default_database=None)`

Despues puedes consultar:

1. `list_databases()`
2. `connect_database("mb_compras")`
3. `list_tables()`
4. `describe_table("Usuarios")`
5. `sample_table("Usuarios", limit=10)`
6. `run_query('SELECT * FROM "Usuarios" LIMIT 20')`

## Tools disponibles

- `set_connection_config`
- `get_connection_config_status`
- `save_connection`
- `list_connections`
- `use_connection`
- `remove_connection`
- `list_databases`
- `get_active_database`
- `connect_database`
- `list_schemas`
- `list_tables`
- `search_tables`
- `describe_table`
- `describe_foreign_keys`
- `sample_table`
- `run_query`
- `run_query_safe`
- `explain_query`
- `count_rows`

## Seguridad

- `run_query` permite solo `SELECT`.
- Se bloquean multiples sentencias en una sola consulta.
- Campos sensibles se devuelven enmascarados (`***`) en resultados.
- Las conexiones persistentes guardan la contrasena cifrada con `MCP_MASTER_KEY`.

## Notas

- La configuracion de conexion en runtime vive mientras el proceso MCP este encendido.
- Si reinicias el servidor, vuelve a ejecutar `set_connection_config`.
- Si usas `save_connection`, define `MCP_MASTER_KEY` en el entorno del servidor.
