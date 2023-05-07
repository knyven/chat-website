from flask import Flask, render_template, redirect, url_for, request, jsonify, flash
from flask_login import LoginManager, login_required, UserMixin, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
import openai
import click
import os
import json
import requests

app = Flask(__name__)

# Read secret key from local.env file
with open("local.env", "r") as f:
    app.secret_key = f.read().strip()

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///users.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Read API key from local.env file
with open("local.env", "r") as f:
    SECRET_API_KEY = f.read().strip()

openai.api_key = SECRET_API_KEY

# Store the conversation history
conversation_history = [
    {"role": "system", "content": "You are a helpful assistant."},
]

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        user = User.query.filter_by(username=username).first()

        if user and bcrypt.check_password_hash(user.password, password):
            login_user(user)
            flash('Logged in successfully.', 'success')
            return redirect(url_for('chat'))
        else:
            flash('Incorrect username or password.', 'error')
            return redirect(url_for('index'))
    return render_template('index.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('chat'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        new_user = User(username=username, password=hashed_password)

        try:
            db.session.add(new_user)
            db.session.commit()
            flash('Registration successful! Please log in.', 'success')
            return redirect(url_for('login'))
        except:
            flash('Registration failed. Please try again.', 'danger')

    return render_template('register.html')


@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('Logged out successfully.', 'info')
    return redirect(url_for('index'))


@app.route('/chat')
@login_required
def chat():
    return render_template('chat.html')

@app.route('/api/chat', methods=['POST'])
@login_required
def chat_api():
    message = request.json.get('message', '')
    response_text = send_to_chat_gpt(message)
    return jsonify({"response": response_text})

def send_to_chat_gpt(message):
    # Add the user message to the conversation history
    conversation_history.append({"role": "user", "content": message})

    try:
        response = openai.ChatCompletion.create(
            model="gpt-3.5-turbo",
            messages=conversation_history
        )

        # Get the assistant's reply and add it to the conversation history
        assistant_reply = response.choices[0].message["content"].strip()
        conversation_history.append({"role": "assistant", "content": assistant_reply})

        return assistant_reply
    except Exception as e:
        print("Error:", e)
        return "Error: Unable to get a response from ChatGPT"
    

def create_test_user(username, password):
    # Check if the user already exists
    user = User.query.filter_by(username=username).first()

    if not user:
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        test_user = User(username=username, password=hashed_password)
        db.session.add(test_user)
        db.session.commit()
        print(f"Test user '{username}' created.")
    else:
        print(f"Test user '{username}' already exists.")

# Add a new CLI command to create a test user
@app.cli.command("create-test-user")
@click.argument("username")
@click.argument("password")
def create_test_user_cli(username, password):
    create_test_user(username, password)

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
        create_test_user("testuser", "testpassword")  # Create a test user
    app.run(debug=True)
