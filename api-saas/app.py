from flask import Flask, jsonify, request
import pymysql

app = Flask(__name__)

def get_db_connection():
    return pymysql.connect(
        host='mysql-db',
        user='admin',
        password='mockupsaa',
        database='saas',
        cursorclass=pymysql.cursors.DictCursor
    )

def build_query(table, filters, created_from=None, created_to=None, order_field="created_at"):
    base_query = f"SELECT * FROM {table} WHERE 1=1"
    params = []

    for field, value in filters.items():
        if value is not None:
            base_query += f" AND {field} = %s"
            params.append(value)

    if created_from:
        base_query += " AND created_at >= %s"
        params.append(created_from)
    if created_to:
        base_query += " AND created_at <= %s"
        params.append(created_to)

    base_query += f" ORDER BY {order_field} DESC LIMIT %s OFFSET %s"
    return base_query, params

@app.route('/')
def index():
    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute("SELECT DATABASE() AS db;")
        result = cursor.fetchone()
    connection.close()
    return jsonify(result)

# ======== ENDPOINTS PARA TABLAS ========

@app.route('/entries', methods=['GET'])
def get_entries():
    filters = {
        "id": request.args.get("id"),
        "package_id": request.args.get("package_id"),
        "tipo": request.args.get("tipo"),
        "modo": request.args.get("modo"),
        "restaurada": request.args.get("restaurada")
    }
    created_from = request.args.get("created_from")  
    created_to = request.args.get("created_to")      
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    query, params = build_query("entries", filters, created_from, created_to)
    params.extend([limit, offset])

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute(query, params)
        result = cursor.fetchall()
    connection.close()
    return jsonify(result)

@app.route('/detections', methods=['GET'])
def get_detections():
    # Leer filtros
    filters = {
        "id": request.args.get("id"),
        "package_id": request.args.get("package_id"),
        "intrusismo": request.args.get("intrusismo"),
        "umbral": request.args.get("umbral"),
        "restaurado": request.args.get("restaurado"),
        "sensor_tipo": request.args.get("sensor_tipo"),
        "sensor_estado": request.args.get("sensor_estado"),
        "terminal_nombre": request.args.get("terminal_nombre"),
        "created_from": request.args.get("created_from"),
        "created_to": request.args.get("created_to"),
    }
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    # Base de la consulta
    query = """
        SELECT 
            d.id AS detection_id,
            d.entry_id,
            d.package_id,
            d.intrusismo,
            d.umbral,
            d.restaurado,
            d.modo_deteccion,
            d.fecha,
            s.id AS sensor_id,
            s.tipo AS sensor_tipo,
            s.estado AS sensor_estado,
            s.valor_sensor,
            t.id AS terminal_id,
            t.nombre_terminal
        FROM detections d
        JOIN sensors s ON s.detection_id = d.id
        LEFT JOIN terminals t ON s.terminal_id = t.id
    """

    # Construir cláusula WHERE dinámica
    where_clauses = []
    params = []

    # Filtro específico por ID de detección (tabla detections)
    if filters["id"] is not None:
        where_clauses.append("d.id = %s")
        params.append(filters["id"])

    # Filtro específico por package_id de detections
    if filters["package_id"] is not None:
        where_clauses.append("d.package_id = %s")
        params.append(filters["package_id"])

    if filters["intrusismo"] is not None:
        where_clauses.append("d.intrusismo = %s")
        params.append(filters["intrusismo"])

    if filters["umbral"] is not None:
        where_clauses.append("d.umbral = %s")
        params.append(filters["umbral"])

    if filters["restaurado"] is not None:
        where_clauses.append("d.restaurado = %s")
        params.append(filters["restaurado"])

    if filters["sensor_tipo"] is not None:
        where_clauses.append("s.tipo = %s")
        params.append(filters["sensor_tipo"])

    if filters["sensor_estado"] is not None:
        where_clauses.append("s.estado = %s")
        params.append(filters["sensor_estado"])

    if filters["terminal_nombre"] is not None:
        where_clauses.append("t.nombre_terminal LIKE %s")
        params.append(f"%{filters['terminal_nombre']}%")

    if filters["created_from"] is not None:
        where_clauses.append("d.fecha >= %s")
        params.append(filters["created_from"])

    if filters["created_to"] is not None:
        where_clauses.append("d.fecha <= %s")
        params.append(filters["created_to"])

    if where_clauses:
        query += " WHERE " + " AND ".join(where_clauses)

    query += " ORDER BY d.fecha DESC LIMIT %s OFFSET %s;"
    params.extend([limit, offset])

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute(query, params)
        result = cursor.fetchall()
    connection.close()

    return jsonify(result)

@app.route('/logs', methods=['GET'])
def get_logs():
    filters = {
        "id": request.args.get("id"),
        "package_id": request.args.get("package_id"),
        "descripcion": request.args.get("descripcion")
    }
    created_from = request.args.get("created_from")
    created_to = request.args.get("created_to")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    query, params = build_query("logs", filters, created_from, created_to)
    params.extend([limit, offset])

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute(query, params)
        result = cursor.fetchall()
    connection.close()
    return jsonify(result)

@app.route('/notices', methods=['GET'])
def get_notices():
    filters = {
        "id": request.args.get("id"),
        "package_id": request.args.get("package_id"),
        "tipo": request.args.get("tipo"),
        "telefono": request.args.get("telefono")
    }
    created_from = request.args.get("created_from")
    created_to = request.args.get("created_to")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    query, params = build_query("notices", filters, created_from, created_to)
    params.extend([limit, offset])

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute(query, params)
        result = cursor.fetchall()
    connection.close()
    return jsonify(result)

@app.route('/packages', methods=['GET'])
def get_packages():
    filters = {
        "id": request.args.get("id"),
        "implantado": request.args.get("implantado"),
        "saa_version": request.args.get("saa_version")
    }
    created_from = request.args.get("created_from")
    created_to = request.args.get("created_to")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    query, params = build_query("packages", filters, created_from, created_to)
    params.extend([limit, offset])

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute(query, params)
        result = cursor.fetchall()
        
        # Check each package if it exists in related tables
        for package in result:
            package_id = package['id']
            # Check in entries, detections, notices, and logs tables
            cursor.execute("""
                SELECT EXISTS(SELECT 1 FROM entries WHERE package_id = %s) AS in_entries,
                       EXISTS(SELECT 1 FROM detections WHERE package_id = %s) AS in_detections,
                       EXISTS(SELECT 1 FROM notices WHERE package_id = %s) AS in_notices,
                       EXISTS(SELECT 1 FROM logs WHERE package_id = %s) AS in_logs
            """, (package_id, package_id, package_id, package_id))
            
            exists = cursor.fetchone()
            # If any of the exists checks is True (1), then vacio = 0, else 1
            package['vacio'] = 0 if any(exists.values()) else 1
            
    connection.close()
    return jsonify(result)

@app.route('/applogs', methods=['GET'])
def get_applogs():
    filters = {
        "id": request.args.get("id"),
        "tipo": request.args.get("tipo"),
        "desc": request.args.get("desc")
    }
    created_from = request.args.get("created_from")
    created_to = request.args.get("created_to")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    query, params = build_query("applogs", filters, created_from, created_to)
    params.extend([limit, offset])

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute(query, params)
        result = cursor.fetchall()
    connection.close()
    return jsonify(result)

@app.route('/system_notices', methods=['GET'])
def get_system_notices():
    filters = {
        "id": request.args.get("id"),
        "tipo": request.args.get("tipo"),
        "procesado": request.args.get("procesado")
    }
    created_from = request.args.get("created_from")
    created_to = request.args.get("created_to")
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    query, params = build_query("system_notices", filters, created_from, created_to)
    params.extend([limit, offset])

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute(query, params)
        result = cursor.fetchall()
    connection.close()
    return jsonify(result)

@app.route('/systems', methods=['GET'])
def get_systems():
    filters = {
        "MODO_ALARMA": request.args.get("MODO_ALARMA"),
        "MODO_SENSIBLE": request.args.get("MODO_SENSIBLE")
    }
    limit = int(request.args.get("limit", 50))
    offset = int(request.args.get("offset", 0))

    query, params = build_query("systems", filters)
    params.extend([limit, offset])

    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute(query, params)
        result = cursor.fetchall()
    connection.close()
    return jsonify(result)

@app.route('/alarms', methods=['GET'])
def get_alarms():
    connection = get_db_connection()
    with connection.cursor() as cursor:
        cursor.execute("SELECT * FROM alarms;")
        result = cursor.fetchall()
    connection.close()
    return jsonify(result)

@app.route('/packages/<int:package_id>/details', methods=['GET'])
def get_package_details(package_id):
    """Devuelve datos agregados del paquete y sus recursos asociados.

    Params opcionales:
      - include: lista separada por comas (entries,detections,logs,notices)
      - created_from, created_to: filtros de fecha (aplican a tablas con created_at; en detections filtra por d.fecha)
      - Paginación por colección:
          limit_entries, offset_entries
          limit_detections, offset_detections
          limit_logs, offset_logs
          limit_notices, offset_notices
    """

    include_param = request.args.get('include', 'entries,detections,logs,notices')
    include = {part.strip() for part in include_param.split(',') if part.strip()}

    created_from = request.args.get('created_from')
    created_to = request.args.get('created_to')

    # Límites por colección
    limit_entries = int(request.args.get('limit_entries', 50))
    offset_entries = int(request.args.get('offset_entries', 0))

    limit_detections = int(request.args.get('limit_detections', 50))
    offset_detections = int(request.args.get('offset_detections', 0))

    limit_logs = int(request.args.get('limit_logs', 50))
    offset_logs = int(request.args.get('offset_logs', 0))

    limit_notices = int(request.args.get('limit_notices', 50))
    offset_notices = int(request.args.get('offset_notices', 0))

    response = {}

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Paquete
            cursor.execute("SELECT * FROM packages WHERE id = %s", (package_id,))
            response["package"] = cursor.fetchone()

            # Entries
            if 'entries' in include:
                filters_entries = {"package_id": package_id}
                query_entries, params_entries = build_query("entries", filters_entries, created_from, created_to)
                params_entries.extend([limit_entries, offset_entries])
                cursor.execute(query_entries, params_entries)
                response["entries"] = cursor.fetchall()

            # Detections (usa d.package_id y fecha en d.fecha)
            if 'detections' in include:
                query_det = """
                    SELECT 
                        d.id AS detection_id,
                        d.entry_id,
                        d.package_id,
                        d.intrusismo,
                        d.umbral,
                        d.restaurado,
                        d.modo_deteccion,
                        d.fecha
                    FROM detections d
                    WHERE d.package_id = %s
                """
                params_det = [package_id]
                if created_from:
                    query_det += " AND d.fecha >= %s"
                    params_det.append(created_from)
                if created_to:
                    query_det += " AND d.fecha <= %s"
                    params_det.append(created_to)
                query_det += " ORDER BY d.fecha DESC LIMIT %s OFFSET %s"
                params_det.extend([limit_detections, offset_detections])
                cursor.execute(query_det, params_det)
                response["detections"] = cursor.fetchall()

            # Logs
            if 'logs' in include:
                filters_logs = {"package_id": package_id}
                query_logs, params_logs = build_query("logs", filters_logs, created_from, created_to)
                params_logs.extend([limit_logs, offset_logs])
                cursor.execute(query_logs, params_logs)
                response["logs"] = cursor.fetchall()

            # Notices
            if 'notices' in include:
                filters_notices = {"package_id": package_id}
                query_notices, params_notices = build_query("notices", filters_notices, created_from, created_to)
                params_notices.extend([limit_notices, offset_notices])
                cursor.execute(query_notices, params_notices)
                response["notices"] = cursor.fetchall()

            # Counts (ignoran paginación)
            counts = {}
            # Entries count
            count_q = "SELECT COUNT(*) AS count FROM entries WHERE 1=1 AND package_id = %s"
            count_p = [package_id]
            if created_from:
                count_q += " AND created_at >= %s"
                count_p.append(created_from)
            if created_to:
                count_q += " AND created_at <= %s"
                count_p.append(created_to)
            cursor.execute(count_q, count_p)
            counts["entries"] = cursor.fetchone()["count"]

            # Detections count
            count_q = "SELECT COUNT(*) AS count FROM detections d WHERE d.package_id = %s"
            count_p = [package_id]
            if created_from:
                count_q += " AND d.fecha >= %s"
                count_p.append(created_from)
            if created_to:
                count_q += " AND d.fecha <= %s"
                count_p.append(created_to)
            cursor.execute(count_q, count_p)
            counts["detections"] = cursor.fetchone()["count"]

            # Logs count
            count_q = "SELECT COUNT(*) AS count FROM logs WHERE 1=1 AND entry_id IS NOT NULL AND package_id = %s".replace(" AND entry_id IS NOT NULL", "")
            count_q = "SELECT COUNT(*) AS count FROM logs WHERE 1=1 AND package_id = %s"
            count_p = [package_id]
            if created_from:
                count_q += " AND created_at >= %s"
                count_p.append(created_from)
            if created_to:
                count_q += " AND created_at <= %s"
                count_p.append(created_to)
            cursor.execute(count_q, count_p)
            counts["logs"] = cursor.fetchone()["count"]

            # Notices count
            count_q = "SELECT COUNT(*) AS count FROM notices WHERE 1=1 AND package_id = %s"
            count_p = [package_id]
            if created_from:
                count_q += " AND created_at >= %s"
                count_p.append(created_from)
            if created_to:
                count_q += " AND created_at <= %s"
                count_p.append(created_to)
            cursor.execute(count_q, count_p)
            counts["notices"] = cursor.fetchone()["count"]

            response["counts"] = counts

    finally:
        connection.close()

    return jsonify(response)

@app.route('/entries/<int:entry_id>/details', methods=['GET'])
def get_entry_details(entry_id):
    """Devuelve datos agregados de un entry y sus recursos relacionados por entry_id.

    Params opcionales:
      - include: lista separada por comas (detections,logs,notices)
      - created_from, created_to: rango de fechas (aplica a created_at en logs/notices; en detections a d.fecha)
      - Paginación por colección:
          limit_detections, offset_detections
          limit_logs, offset_logs
          limit_notices, offset_notices
    """

    include_param = request.args.get('include', 'detections,logs,notices')
    include = {part.strip() for part in include_param.split(',') if part.strip()}

    created_from = request.args.get('created_from')
    created_to = request.args.get('created_to')

    limit_detections = int(request.args.get('limit_detections', 50))
    offset_detections = int(request.args.get('offset_detections', 0))

    limit_logs = int(request.args.get('limit_logs', 50))
    offset_logs = int(request.args.get('offset_logs', 0))

    limit_notices = int(request.args.get('limit_notices', 50))
    offset_notices = int(request.args.get('offset_notices', 0))

    response = {}

    connection = get_db_connection()
    try:
        with connection.cursor() as cursor:
            # Entry
            cursor.execute("SELECT * FROM entries WHERE id = %s", (entry_id,))
            response["entry"] = cursor.fetchone()

            # Detections asociadas al entry
            if 'detections' in include:
                query_det = """
                    SELECT 
                        d.id AS detection_id,
                        d.entry_id,
                        d.package_id,
                        d.intrusismo,
                        d.umbral,
                        d.restaurado,
                        d.modo_deteccion,
                        d.fecha
                    FROM detections d
                    WHERE d.entry_id = %s
                """
                params_det = [entry_id]
                if created_from:
                    query_det += " AND d.fecha >= %s"
                    params_det.append(created_from)
                if created_to:
                    query_det += " AND d.fecha <= %s"
                    params_det.append(created_to)
                query_det += " ORDER BY d.fecha DESC LIMIT %s OFFSET %s"
                params_det.extend([limit_detections, offset_detections])
                cursor.execute(query_det, params_det)
                response["detections"] = cursor.fetchall()

            # Logs del entry
            if 'logs' in include:
                filters_logs = {"entry_id": entry_id}
                query_logs, params_logs = build_query("logs", filters_logs, created_from, created_to)
                params_logs.extend([limit_logs, offset_logs])
                cursor.execute(query_logs, params_logs)
                response["logs"] = cursor.fetchall()

            # Notices del entry
            if 'notices' in include:
                filters_notices = {"entry_id": entry_id}
                query_notices, params_notices = build_query("notices", filters_notices, created_from, created_to)
                params_notices.extend([limit_notices, offset_notices])
                cursor.execute(query_notices, params_notices)
                response["notices"] = cursor.fetchall()

            # Counts (ignoran paginación)
            counts = {}
            # Detections count
            count_q = "SELECT COUNT(*) AS count FROM detections d WHERE d.entry_id = %s"
            count_p = [entry_id]
            if created_from:
                count_q += " AND d.fecha >= %s"
                count_p.append(created_from)
            if created_to:
                count_q += " AND d.fecha <= %s"
                count_p.append(created_to)
            cursor.execute(count_q, count_p)
            counts["detections"] = cursor.fetchone()["count"]

            # Logs count
            count_q = "SELECT COUNT(*) AS count FROM logs WHERE 1=1 AND entry_id = %s"
            count_p = [entry_id]
            if created_from:
                count_q += " AND created_at >= %s"
                count_p.append(created_from)
            if created_to:
                count_q += " AND created_at <= %s"
                count_p.append(created_to)
            cursor.execute(count_q, count_p)
            counts["logs"] = cursor.fetchone()["count"]

            # Notices count
            count_q = "SELECT COUNT(*) AS count FROM notices WHERE 1=1 AND entry_id = %s"
            count_p = [entry_id]
            if created_from:
                count_q += " AND created_at >= %s"
                count_p.append(created_from)
            if created_to:
                count_q += " AND created_at <= %s"
                count_p.append(created_to)
            cursor.execute(count_q, count_p)
            counts["notices"] = cursor.fetchone()["count"]

            response["counts"] = counts

    finally:
        connection.close()

    return jsonify(response)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
