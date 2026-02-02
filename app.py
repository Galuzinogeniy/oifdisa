"""
🔐 Сервер аутентификации (для деплоя)
"""

from flask import Flask, request, jsonify
from flask_cors import CORS
import sqlite3
import hashlib
import os

app = Flask(__name__)
CORS(app)

# Путь к базе данных
DATABASE = os.environ.get('DATABASE_PATH', 'users.db')


def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_db_connection()
    conn.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            name TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()
    print("✅ База данных готова!")


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


@app.route('/')
def home():
    return jsonify({
        'message': '🎉 Сервер работает!',
        'endpoints': {
            'POST /register': 'Регистрация',
            'POST /login': 'Вход'
        }
    })


@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'message': 'Нет данных'}), 400
    
    email = data.get('email', '').strip()
    password = data.get('password', '')
    name = data.get('name', '').strip()
    
    if not email or not password or not name:
        return jsonify({'success': False, 'message': 'Заполните все поля'}), 400
    
    if len(password) < 6:
        return jsonify({'success': False, 'message': 'Пароль минимум 6 символов'}), 400
    
    if '@' not in email:
        return jsonify({'success': False, 'message': 'Некорректный email'}), 400
    
    password_hash = hash_password(password)
    
    try:
        conn = get_db_connection()
        conn.execute(
            'INSERT INTO users (email, password_hash, name) VALUES (?, ?, ?)',
            (email, password_hash, name)
        )
        conn.commit()
        
        user = conn.execute(
            'SELECT id, email, name FROM users WHERE email = ?',
            (email,)
        ).fetchone()
        conn.close()
        
        return jsonify({
            'success': True,
            'message': 'Регистрация успешна!',
            'user': {'id': user['id'], 'email': user['email'], 'name': user['name']}
        }), 201
        
    except sqlite3.IntegrityError:
        return jsonify({'success': False, 'message': 'Email уже существует'}), 409


@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    
    if not data:
        return jsonify({'success': False, 'message': 'Нет данных'}), 400
    
    email = data.get('email', '').strip()
    password = data.get('password', '')
    
    if not email or not password:
        return jsonify({'success': False, 'message': 'Введите email и пароль'}), 400
    
    password_hash = hash_password(password)
    
    conn = get_db_connection()
    user = conn.execute(
        'SELECT id, email, name, password_hash FROM users WHERE email = ?',
        (email,)
    ).fetchone()
    conn.close()
    
    if user is None:
        return jsonify({'success': False, 'message': 'Пользователь не найден'}), 404
    
    if user['password_hash'] != password_hash:
        return jsonify({'success': False, 'message': 'Неверный пароль'}), 401
    
    return jsonify({
        'success': True,
        'message': 'Вход выполнен!',
        'user': {'id': user['id'], 'email': user['email'], 'name': user['name']}
    })


# Инициализация БД при старте
with app.app_context():
    init_db()


# Для локального запуска
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port)
