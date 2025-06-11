from flask import Flask, render_template, request, redirect, session, url_for, flash
from datetime import timedelta
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

from werkzeug.security import generate_password_hash, check_password_hash
import re
from flask_wtf import CSRFProtect, FlaskForm
from wtforms import StringField, PasswordField, SelectField, SubmitField
from wtforms.validators import DataRequired, Length, Regexp

from models import db, User, DirectorMessage, TeacherMessage, ChatMessage

import socket


# ---------- SOCKET CONFIG ----------
SERVER_HOST = '10.6.0.118'
SERVER_PORT = 5555

def send_to_socket_server(username, role, class_name, message):
    try:
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client_socket.connect((SERVER_HOST, SERVER_PORT))

        client_socket.recv(1024)
        client_socket.send(username.encode('utf-8'))

        client_socket.recv(1024)
        client_socket.send(role.encode('utf-8'))

        if role in ['student', 'teacher']:
            client_socket.recv(1024)
            client_socket.send(class_name.encode('utf-8'))

        client_socket.send(message.encode('utf-8'))
        client_socket.close()

    except Exception as e:
        print(f"[Ошибка отправки]: {e}")

# ---------- APP CONFIG ----------
def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = '5FhdmfMI8qRuxaumAVHu39uGTglwQ9KsuBPQWFyQ0fw'
    app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///school.db'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=1)

    db.init_app(app)
    csrf = CSRFProtect(app)
    with app.app_context():
        db.create_all()
    return app

app = create_app()
limiter = Limiter(get_remote_address, app=app, default_limits=["200 per day", "50 per hour"])

# --- Forms ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8, message="Пароль должен быть не менее 8 символов")])
    role = SelectField('Role', choices=[('student', 'Student'), ('teacher', 'Teacher'), ('director', 'Director')])
    class_name = StringField('Class', validators=[DataRequired(), Regexp(r'^\d+$', message="Введите только цифры")])
    submit = SubmitField('Зарегистрироваться')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=3, max=50)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=8)])
    submit = SubmitField('Войти')

class MessageForm(FlaskForm):
    message = StringField('Message', validators=[DataRequired(), Length(min=1, max=500)])
    submit = SubmitField('Отправить')


# ---------- SEQURITY --------

"""def is_valid_username(username):
    return re.match(r'^[A-Za-z0-9_]{3,}$', username)
def is_valid_password(password):
    return len(password) >= 6
def is_valid_class(class_name):
    return re.fullmatch(r'\d+', class_name)"""
# ---------- ROUTES ----------

@app.route('/')
@limiter.limit("10 per minute")
def index():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    director_messages = DirectorMessage.query.order_by(DirectorMessage.timestamp.desc()).all()
    return render_template('index.html', user=user, director_messages=director_messages)


@app.route('/registration', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def register():
    form = RegistrationForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data
        role = form.role.data
        class_name = form.class_name.data

        user = User.query.filter_by(username=username).first()
        if user:
            flash("User already exists")
            return redirect(url_for('register'))

        hashed_password = generate_password_hash(password)
        new_user = User(username=username, password=hashed_password, role=role, class_name=class_name)

        db.session.add(new_user)
        db.session.commit()

        flash("Registration succed")
        return redirect(url_for('login'))

    return render_template('registration.html', form=form)


@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    form = LoginForm()

    if form.validate_on_submit():
        username = form.username.data
        password = form.password.data

        user = User.query.filter_by(username=username).first()

        if user and check_password_hash(user.password, password):
            session['user_id'] = user.id
            session['username'] = user.username
            session['role'] = user.role
            session['class_name'] = user.class_name

            flash("Logged in")
            return redirect(url_for('index'))
        else:
            flash("Not correct username or password")
            return redirect(url_for('login'))

    return render_template('login.html', form=form)


@app.route('/logout')
def logout():
    session.clear()
    return redirect(url_for('login'))


@app.route('/post_director_message', methods=['POST'])
def post_director_message():
    if 'username' not in session or session['role'] != 'director':
        return redirect(url_for('login'))

    message = request.form['message']
    new_message = DirectorMessage(sender=session['username'], message=message)
    db.session.add(new_message)
    db.session.commit()

    send_to_socket_server(session['username'], session['role'], session['class_name'], message)
    return redirect(url_for('index'))


@app.route('/teacher_board', methods=['GET', 'POST'])
@limiter.limit("10 per minute")
def teacher_board():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    teacher_messages = TeacherMessage.query.filter_by(class_name=user.class_name).order_by(TeacherMessage.timestamp.desc()).all()
    return render_template('teacher_board.html', user=user, teacher_messages=teacher_messages)


@app.route('/post_teacher_message', methods=['POST'])
def post_teacher_message():
    if 'username' not in session or session['role'] != 'teacher':
        return redirect(url_for('login'))

    message = request.form['message']
    user = User.query.filter_by(username=session['username']).first()
    new_msg = TeacherMessage(sender=user.username, class_name=user.class_name, message=message)
    db.session.add(new_msg)
    db.session.commit()

    send_to_socket_server(user.username, user.role, user.class_name, message)
    return redirect(url_for('teacher_board'))


@app.route('/chats')
@limiter.limit("20 per minute")
def chats():
    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.filter_by(username=session['username']).first()
    if user.role == 'teacher':
        chat_users = User.query.filter_by(role='student', class_name=user.class_name).all()
    elif user.role == 'student':
        chat_users = User.query.filter_by(role='teacher', class_name=user.class_name).all()
    else:
        chat_users = []

    return render_template('chats.html', user=user, chat_users=chat_users)


@app.route('/chat_with_user/<int:user_id>', methods=['GET'])
def chat_with_user(user_id):
    if 'username' not in session:
        return redirect(url_for('login'))

    user = User.query.get(session['user_id'])
    chat_partner = User.query.get(user_id)

    messages = ChatMessage.query.filter(
        ((ChatMessage.sender_id == user.id) & (ChatMessage.receiver_id == chat_partner.id)) |
        ((ChatMessage.sender_id == chat_partner.id) & (ChatMessage.receiver_id == user.id))
    ).order_by(ChatMessage.timestamp.asc()).all()

    return render_template('chat_with_user.html', user=user, chat_partner=chat_partner, messages=messages)


@app.route('/send_chat_message', methods=['POST'])
def send_chat_message():
    if 'username' not in session:
        return redirect(url_for('login'))

    sender = User.query.get(session['user_id'])
    receiver_id = int(request.form['receiver_id'])
    message = request.form['message']

    chat_message = ChatMessage(sender_id=sender.id, receiver_id=receiver_id, message=message)
    db.session.add(chat_message)
    db.session.commit()

    send_to_socket_server(sender.username, sender.role, sender.class_name, message)
    return redirect(url_for('chat_with_user', user_id=receiver_id))


# ---------- RUN ----------
if __name__ == '__main__':
    app.run(debug=True)
