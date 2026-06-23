from flask import Flask, render_template, request, redirect, session, url_for
from flask_bcrypt import Bcrypt
import sqlite3

app = Flask(__name__)
app.secret_key = "my_secret_key"

bcrypt = Bcrypt(app)

# Create database
conn = sqlite3.connect("users.db")
c = conn.cursor()

c.execute('''
CREATE TABLE IF NOT EXISTS users(
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL
)
''')

conn.commit()
conn.close()


# Register
@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        password = request.form['password']

        # Input validation
        if len(username) < 3:
            return "Username must be at least 3 characters"

        if len(password) < 8:
            return "Password must be at least 8 characters"

        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')

        try:
            conn = sqlite3.connect("users.db")
            c = conn.cursor()

            # Parameterized query prevents SQL Injection
            c.execute(
                "INSERT INTO users(username,password) VALUES(?,?)",
                (username, hashed_password)
            )

            conn.commit()
            conn.close()

            return redirect('/login')

        except:
            return "Username already exists"

    return render_template("register.html")


# Login
@app.route('/login', methods=['GET', 'POST'])
def login():

    if request.method == 'POST':

        username = request.form['username']
        password = request.form['password']

        conn = sqlite3.connect("users.db")
        c = conn.cursor()

        c.execute(
            "SELECT password FROM users WHERE username=?",
            (username,)
        )

        user = c.fetchone()
        conn.close()

        if user and bcrypt.check_password_hash(user[0], password):
            session['user'] = username
            return redirect('/home')

        return "Invalid Credentials"

    return render_template("login.html")


# Home Page
@app.route('/home')
def home():

    if 'user' in session:
        return render_template("home.html", user=session['user'])

    return redirect('/login')


# Logout
@app.route('/logout')
def logout():
    session.pop('user', None)
    return redirect('/login')


if __name__ == '__main__':
    app.run(debug=True)