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
    connection.close()
    return jsonify(result)

@app.route('/applogs', methods=['GET'])
def get_applogs():
    filters = {
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

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
