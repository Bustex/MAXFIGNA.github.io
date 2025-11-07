from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
import sqlite3
import hashlib
import uuid
from datetime import datetime
import os

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
socketio = SocketIO(app)

# Инициализация базы данных
def init_db():
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()
    
    # Таблица пользователей
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT UNIQUE NOT NULL,
                  password TEXT NOT NULL,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Таблица сообщений
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  sender_id INTEGER NOT NULL,
                  receiver_id INTEGER NOT NULL,
                  message TEXT NOT NULL,
                  timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                  FOREIGN KEY (sender_id) REFERENCES users (id),
                  FOREIGN KEY (receiver_id) REFERENCES users (id))''')
    
    conn.commit()
    conn.close()

# Хеширование пароля
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Проверка пароля
def verify_password(password, hashed):
    return hash_password(password) == hashed

# Получение пользователя по имени
def get_user_by_username(username):
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE username = ?", (username,))
    user = c.fetchone()
    conn.close()
    return user

# Получение пользователя по ID
def get_user_by_id(user_id):
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()
    c.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    user = c.fetchone()
    conn.close()
    return user

# Сохранение сообщения
def save_message(sender_id, receiver_id, message):
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()
    c.execute("INSERT INTO messages (sender_id, receiver_id, message) VALUES (?, ?, ?)",
              (sender_id, receiver_id, message))
    conn.commit()
    message_id = c.lastrowid
    conn.close()
    return message_id

# Получение истории сообщений
def get_message_history(user1_id, user2_id):
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()
    c.execute('''SELECT m.*, u1.username as sender_name, u2.username as receiver_name
                 FROM messages m
                 JOIN users u1 ON m.sender_id = u1.id
                 JOIN users u2 ON m.receiver_id = u2.id
                 WHERE (m.sender_id = ? AND m.receiver_id = ?) 
                    OR (m.sender_id = ? AND m.receiver_id = ?)
                 ORDER BY m.timestamp''',
              (user1_id, user2_id, user2_id, user1_id))
    messages = c.fetchall()
    conn.close()
    return messages

# Поиск пользователей
def search_users(query, current_user_id):
    conn = sqlite3.connect('messenger.db')
    c = conn.cursor()
    c.execute("SELECT id, username FROM users WHERE username LIKE ? AND id != ?", 
              (f'%{query}%', current_user_id))
    users = c.fetchall()
    conn.close()
    return users

@app.route('/')
def index():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    return redirect(url_for('login'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = get_user_by_username(username)
        if user and verify_password(password, user[2]):
            session['user_id'] = user[0]
            session['username'] = user[1]
            return redirect(url_for('chat'))
        else:
            return render_template('login.html', error='Неверное имя пользователя или пароль')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            return render_template('register.html', error='Пароли не совпадают')
        
        if get_user_by_username(username):
            return render_template('register.html', error='Пользователь с таким именем уже существует')
        
        hashed_password = hash_password(password)
        conn = sqlite3.connect('messenger.db')
        c = conn.cursor()
        c.execute("INSERT INTO users (username, password) VALUES (?, ?)", 
                  (username, hashed_password))
        conn.commit()
        conn.close()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    return render_template('chat.html', username=session['username'])

@app.route('/search')
def search():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    query = request.args.get('q', '')
    users = []
    if query:
        users = search_users(query, session['user_id'])
    
    return render_template('search.html', users=users, query=query)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/messages/<int:user_id>')
def get_messages(user_id):
    if 'user_id' not in session:
        return jsonify({'error': 'Не авторизован'}), 401
    
    messages = get_message_history(session['user_id'], user_id)
    message_list = []
    for msg in messages:
        message_list.append({
            'id': msg[0],
            'sender_id': msg[1],
            'receiver_id': msg[2],
            'message': msg[3],
            'timestamp': msg[4],
            'sender_name': msg[5],
            'is_own': msg[1] == session['user_id']
        })
    
    return jsonify(message_list)

@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        join_room(str(session['user_id']))
        print(f"User {session['username']} connected")

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        print(f"User {session['username']} disconnected")

@socketio.on('send_message')
def handle_send_message(data):
    if 'user_id' not in session:
        return
    
    receiver_id = data['receiver_id']
    message = data['message']
    
    # Сохраняем сообщение в БД
    message_id = save_message(session['user_id'], receiver_id, message)
    
    # Отправляем сообщение отправителю
    emit('new_message', {
        'id': message_id,
        'sender_id': session['user_id'],
        'receiver_id': receiver_id,
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'sender_name': session['username'],
        'is_own': True
    }, room=str(session['user_id']))
    
    # Отправляем сообщение получателю
    emit('new_message', {
        'id': message_id,
        'sender_id': session['user_id'],
        'receiver_id': receiver_id,
        'message': message,
        'timestamp': datetime.now().isoformat(),
        'sender_name': session['username'],
        'is_own': False
    }, room=str(receiver_id))

if __name__ == '__main__':
    init_db()
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)
