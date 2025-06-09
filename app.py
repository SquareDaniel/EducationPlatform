import os
import sqlite3
import hashlib
from flask import Flask, request, redirect, url_for, session, g, render_template

app = Flask(__name__)
app.secret_key = 'dev'
DATABASE = os.path.join(os.path.dirname(__file__), 'users.db')


def get_db():
    if 'db' not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(error):
    db = g.pop('db', None)
    if db is not None:
        db.close()


def init_db():
    db = get_db()
    db.execute(
        """CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )"""
    )
    db.commit()


@app.before_request
def load_logged_in_user():
    g.user = None
    user_id = session.get('user_id')
    if user_id is not None:
        user = get_db().execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
        g.user = user


@app.route('/')
def index():
    if g.user:
        return render_template('index.html', username=g.user['username'])
    return render_template('index.html', username=None)


@app.route('/register', methods=['GET', 'POST'])
def register():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        if not username or not password:
            error = 'Username and password required.'
        else:
            try:
                hashed = hashlib.sha256(password.encode()).hexdigest()
                db = get_db()
                db.execute('INSERT INTO users (username, password) VALUES (?, ?)', (username, hashed))
                db.commit()
                return redirect(url_for('login'))
            except sqlite3.IntegrityError:
                error = 'Username already taken.'
    return render_template('register.html', error=error)


@app.route('/login', methods=['GET', 'POST'])
def login():
    error = None
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed = hashlib.sha256(password.encode()).hexdigest()
        user = get_db().execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hashed)).fetchone()
        if user is None:
            error = 'Invalid credentials.'
        else:
            session.clear()
            session['user_id'] = user['id']
            return redirect(url_for('index'))
    return render_template('login.html', error=error)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        init_db()
    app.run()
