from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from flask_socketio import SocketIO, emit, join_room, leave_room
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import sqlite3
import os
from datetime import datetime
import uuid

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here-change-in-production'
app.config['UPLOAD_FOLDER'] = 'static/uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max file size
socketio = SocketIO(app)

# Allowed file extensions for upload
ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp', 'pdf', 'txt', 'doc', 'docx', 'zip'}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def is_image_file(filename):
    if '.' in filename:
        ext = filename.rsplit('.', 1)[1].lower()
        return ext in {'png', 'jpg', 'jpeg', 'gif', 'bmp', 'webp'}
    return False

# Database initialization
def init_db():
    conn = sqlite3.connect('chat.db')
    c = conn.cursor()
    
    # Users table
    c.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    
    # Messages table - updated to include file information
    c.execute('''
        CREATE TABLE IF NOT EXISTS messages (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER NOT NULL,
            username TEXT NOT NULL,
            content TEXT NOT NULL,
            timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            room TEXT DEFAULT 'general',
            file_name TEXT,
            file_path TEXT,
            file_type TEXT,
            file_size INTEGER,
            FOREIGN KEY (user_id) REFERENCES users (id)
        )
    ''')
    
    # Create default rooms
    default_rooms = ['general', 'random', 'help']
    for room in default_rooms:
        c.execute('INSERT OR IGNORE INTO messages (user_id, username, content, room) VALUES (?, ?, ?, ?)',
                 (0, 'System', f'Welcome to #{room}!', room))
    
    conn.commit()
    conn.close()

# Database helper functions
def get_db():
    conn = sqlite3.connect('chat.db')
    conn.row_factory = sqlite3.Row
    return conn

# Routes
@app.route('/')
def index():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    return redirect(url_for('chat'))

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        conn = get_db()
        user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        if user and check_password_hash(user['password_hash'], password):
            session['user_id'] = user['id']
            session['username'] = user['username']
            return redirect(url_for('chat'))
        else:
            return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if 'user_id' in session:
        return redirect(url_for('chat'))
    
    if request.method == 'POST':
        username = request.form['username']
        email = request.form['email']
        password = request.form['password']
        confirm_password = request.form['confirm_password']
        
        if password != confirm_password:
            return render_template('signup.html', error='Passwords do not match')
        
        password_hash = generate_password_hash(password)
        
        conn = get_db()
        try:
            conn.execute('INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)',
                        (username, email, password_hash))
            conn.commit()
            
            user = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
            session['user_id'] = user['id']
            session['username'] = user['username']
            conn.close()
            
            return redirect(url_for('chat'))
        except sqlite3.IntegrityError:
            conn.close()
            return render_template('signup.html', error='Username or email already exists')
    
    return render_template('signup.html')

@app.route('/chat')
def chat():
    if 'user_id' not in session:
        return redirect(url_for('login'))
    
    conn = get_db()
    rooms = conn.execute('SELECT DISTINCT room FROM messages ORDER BY room').fetchall()
    recent_messages = conn.execute(
        'SELECT m.*, u.username FROM messages m JOIN users u ON m.user_id = u.id WHERE m.room = ? ORDER BY m.timestamp DESC LIMIT 50',
        ('general',)
    ).fetchall()
    conn.close()
    
    return render_template('chat.html', 
                          username=session['username'],
                          rooms=[room['room'] for room in rooms],
                          messages=recent_messages)

@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))

@app.route('/api/messages/<room>')
def get_messages(room):
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = get_db()
    messages = conn.execute(
        'SELECT m.id, m.content, m.timestamp, u.username, m.file_name, m.file_path, m.file_type, m.file_size FROM messages m JOIN users u ON m.user_id = u.id WHERE m.room = ? ORDER BY m.timestamp DESC LIMIT 100',
        (room,)
    ).fetchall()
    conn.close()
    
    return jsonify([dict(msg) for msg in messages])

@app.route('/api/rooms')
def get_rooms():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    conn = get_db()
    rooms = conn.execute('SELECT DISTINCT room FROM messages ORDER BY room').fetchall()
    conn.close()
    
    return jsonify([room['room'] for room in rooms])

@app.route('/api/upload', methods=['POST'])
def upload_file():
    if 'user_id' not in session:
        return jsonify({'error': 'Not authenticated'}), 401
    
    if 'file' not in request.files:
        return jsonify({'error': 'No file part'}), 400
    
    file = request.files['file']
    room = request.form.get('room', 'general')
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'File type not allowed'}), 400
    
    # Create upload directory if it doesn't exist
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    
    # Generate unique filename to prevent collisions
    filename = secure_filename(file.filename)
    unique_filename = f"{uuid.uuid4().hex}_{filename}"
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], unique_filename)
    
    # Save file
    file.save(file_path)
    file_size = os.path.getsize(file_path)
    
    # Store in database
    conn = get_db()
    cursor = conn.execute(
        'INSERT INTO messages (user_id, username, content, room, file_name, file_path, file_type, file_size) VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
        (session['user_id'], session['username'], filename, room, filename, file_path, file.content_type, file_size)
    )
    conn.commit()
    message_id = cursor.lastrowid
    conn.close()
    
    # Prepare message data for real-time update
    message_data = {
        'id': message_id,
        'username': session['username'],
        'content': filename,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'room': room,
        'file_name': filename,
        'file_path': file_path.replace('\\', '/'),  # Ensure forward slashes for URLs
        'file_type': file.content_type,
        'file_size': file_size,
        'is_file': True
    }
    
    # Emit to room
    socketio.emit('new_message', message_data, room=room)
    
    return jsonify({
        'success': True,
        'message': message_data
    })

# SocketIO events
@socketio.on('connect')
def handle_connect():
    if 'user_id' in session:
        join_room(session.get('current_room', 'general'))
        emit('user_status', {
            'username': session['username'],
            'status': 'online'
        }, broadcast=True)

@socketio.on('disconnect')
def handle_disconnect():
    if 'user_id' in session:
        emit('user_status', {
            'username': session['username'],
            'status': 'offline'
        }, broadcast=True)

@socketio.on('join_room')
def handle_join_room(data):
    room = data['room']
    session['current_room'] = room
    join_room(room)
    
    conn = get_db()
    recent_messages = conn.execute(
        'SELECT m.id, m.content, m.timestamp, u.username, m.file_name, m.file_path, m.file_type, m.file_size FROM messages m JOIN users u ON m.user_id = u.id WHERE m.room = ? ORDER BY m.timestamp DESC LIMIT 50',
        (room,)
    ).fetchall()
    conn.close()
    
    emit('room_history', {
        'room': room,
        'messages': [dict(msg) for msg in recent_messages]
    })
    
    emit('system_message', {
        'room': room,
        'message': f'{session["username"]} joined the room'
    }, room=room)

@socketio.on('leave_room')
def handle_leave_room(data):
    room = data['room']
    leave_room(room)
    emit('system_message', {
        'room': room,
        'message': f'{session["username"]} left the room'
    }, room=room)

@socketio.on('send_message')
def handle_send_message(data):
    if 'user_id' not in session:
        return
    
    room = data.get('room', 'general')
    content = data['content'].strip()
    
    if not content:
        return
    
    conn = get_db()
    conn.execute('INSERT INTO messages (user_id, username, content, room) VALUES (?, ?, ?, ?)',
                (session['user_id'], session['username'], content, room))
    conn.commit()
    
    message = {
        'id': conn.execute('SELECT last_insert_rowid()').fetchone()[0],
        'username': session['username'],
        'content': content,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        'room': room,
        'is_file': False
    }
    conn.close()
    
    emit('new_message', message, room=room)

if __name__ == '__main__':
    if not os.path.exists('chat.db'):
        init_db()
    # Create uploads directory if it doesn't exist
    if not os.path.exists(app.config['UPLOAD_FOLDER']):
        os.makedirs(app.config['UPLOAD_FOLDER'])
    socketio.run(app, debug=True, host='0.0.0.0', port=5001)
