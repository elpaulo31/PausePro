from flask import Flask, request, jsonify, render_template
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
import ast
import datetime
from flask_cors import CORS
import sqlite3
from dotenv import load_dotenv
import os
load_dotenv()

app = Flask(__name__)
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET')
jwt = JWTManager(app)
# CORS(app)  # Permitir requisições CORS durante o desenvolvimento

# Conectar ao banco de dados
def init_db():
    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            employee_id TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            name TEXT NOT NULL
        )
        """)
        cursor.execute("""
        CREATE TABLE IF NOT EXISTS time_recording(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            entry TIMESTAMP,
            lunch_break_entry TIMESTAMP,
            lunch_break_exit TIMESTAMP,
            exit TIMESTAMP,
            created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
        )
        """)
        conn.commit()

# Inicializar o banco de dados na primeira execução
init_db()

# Rota para autenticação de usuários (API)
@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json()
    employee_id = data.get("employeeId")
    password = data.get("password")

    with sqlite3.connect("database.db") as conn:
        cursor = conn.cursor()
        cursor.execute("SELECT name, id FROM users WHERE employee_id = ? AND password = ?", (employee_id, password))
        user = cursor.fetchone()

    userInfo = {
        "id": user[1]
    }
    accessToken = create_access_token(identity=str(userInfo))
    if user:
        return jsonify({"success": True, "message": "Login successful", "accessToken": accessToken}), 200
    else:
        return jsonify({"success": False, "message": "Invalid ID or password"}), 401

# Rota para cadastro de usuários (API)
@app.route('/api/register', methods=['POST'])
def register():
    data = request.get_json()
    employee_id = data.get("employeeId")
    password = data.get("password")
    name = data.get("name")

    if not employee_id or not password or not name:
        return jsonify({"success": False, "message": "All fields are required"}), 400

    try:
        with sqlite3.connect("database.db") as conn:
            cursor = conn.cursor()
            cursor.execute("INSERT INTO users (employee_id, password, name) VALUES (?, ?, ?)", 
                           (employee_id, password, name))
            conn.commit()
        return jsonify({"success": True, "message": "User registered successfully"}), 201
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "Employee ID already exists"}), 409

#front
# Rota para a Home
@app.route('/')
def home():
    return render_template('index.html')

# Rota para a Tela de Login
@app.route('/login', methods=['POST'])
def login_page():

    employeeName = request.form.get('employeeName')
    employee_id = request.form.get('employeeId')
    password = request.form.get('password')

    
    # Aqui você pode fazer validação/autenticação
    if employeeName== 'admin' and employee_id == 'admin' and password == '1234':
        return render_template('home.html')
    #return render_template('login.html')
    else:
        return jsonify({"message": "Invalid credentials!"}), 401
        

@app.route('/api/timeRecord' ,methods=['POST'])
@jwt_required()
def timeRecord():
    data = request.get_json()
    action = data.get('action')
    current_user = ast.literal_eval(get_jwt_identity())
    current_time = datetime.datetime.now()

    try:
        with sqlite3.connect('database.db') as conn:
            cursor = conn.cursor()

            # Verificar se já existe um registro para hoje
            cursor.execute("""
                SELECT id, entry, lunch_break_entry, lunch_break_exit, exit
                FROM time_recording
                WHERE user_id = ? AND DATE(entry) = DATE('now')
            """, (current_user['id'],))
            record = cursor.fetchone()

            if record:
                # Atualizar o registro existente
                record_id = record[0]
                if action == "entry" and not record[1]:
                    cursor.execute("UPDATE time_recording SET entry = ? WHERE id = ?", (current_time, record_id))
                elif action == "lunch_break_entry" and not record[2]:
                    cursor.execute("UPDATE time_recording SET lunch_break_entry = ? WHERE id = ?", (current_time, record_id))
                elif action == "lunch_break_exit" and not record[3]:
                    cursor.execute("UPDATE time_recording SET lunch_break_exit = ? WHERE id = ?", (current_time, record_id))
                elif action == "exit" and not record[4]:
                    cursor.execute("UPDATE time_recording SET exit = ? WHERE id = ?", (current_time, record_id))
                else:
                    return jsonify({"success": False, "message": "Action already recorded or invalid"}), 400
            else:
                # Inserir um novo registro
                if action == "entry":
                    cursor.execute("""
                        INSERT INTO time_recording (user_id, entry)
                        VALUES (?, ?)
                    """, (current_user['id'], current_time))
                else:
                    return jsonify({"success": False, "message": "Entry must be recorded first"}), 400

            conn.commit()
            return jsonify({"success": True, "message": "Time recorded successfully"}), 200

    except sqlite3.Error as e:
        return jsonify({"success": False, "message": f"Database error: {str(e)}"}), 500


if __name__ == '__main__':
    app.run(debug=True)
