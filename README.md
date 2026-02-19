# Discord-like Chat Application

A real-time chat application built with Flask and SocketIO, featuring user authentication and multiple chat rooms.

Running this will handle the server.

## Features

- User authentication (login/signup)
- Real-time messaging using WebSockets
- Multiple chat rooms
- Online user status
- **File upload support** (images, documents, etc.)
- **Image display in chat with modal viewer**
- Responsive design
- SQLite database for data persistence

## Installation

1. Create a virtual environment:
```
python3 -m venv .venv # or python -m venv .venv if you are on windows
```

2. Install requirements
```
pip install -r requirements.txt
```

3. Run the server
```
python3 app.py
```

4. You're good!

## File Upload Features

- Upload files up to 16MB
- Supported file types: PNG, JPG, JPEG, GIF, BMP, WEBP, PDF, TXT, DOC, DOCX, ZIP
- Images are displayed directly in the chat
- Non-image files appear as clickable links
- Click on uploaded images to view them in a modal viewer
- File sizes are displayed for non-image files
