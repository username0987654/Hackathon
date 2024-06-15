
import os
from flask import Flask, request, render_template, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from flask_migrate import Migrate
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user

app = Flask(__name__)

app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URI', 'sqlite:///users.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY', 'your-secret-key')

db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), nullable=False)
    grade = db.Column(db.String(80), nullable=False)
    email = db.Column(db.String(120), nullable=False, unique=True)
    password = db.Column(db.String(200), nullable=False)
    subject = db.Column(db.String(50), nullable=True)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/math')
def math():
    return render_template('math.html')

@app.route('/sci')
def sci():
    return render_template('sci.html')

@app.route('/phil')
def phil():
    return render_template('phil.html')

@app.route('/eng')
def eng():
    return render_template('eng.html')

@app.route('/soci')
def soci():
    return render_template('soci.html')

@app.route('/nhome')
def nhome():
    return render_template('nhome.html')

@app.route('/home')
def home():
    return render_template('home.html')

@app.route('/susers')
def susers():
    return render_template('susers.html')

@app.route('/choose')
def choose():
    return render_template('choose.html')

@app.route('/first')
def first():
    return render_template('first.html')

@app.route('/login_m')
def login_m():
    return render_template('login_m.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form['username']
        grade = request.form['grade']
        email = request.form['email']
        password = request.form['password']
        hashed_password = generate_password_hash(password, method='pbkdf2:sha256')

        new_user = User(username=username, grade=grade, email=email, password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        
        login_user(new_user)
        return redirect(url_for('choose'))

    return render_template('signup.html')

@app.route('/users')
def users():
    search_query = request.args.get('search')
    if search_query:
        all_users = User.query.filter(
            (User.username.contains(search_query)) |
            (User.email.contains(search_query)) |
            (User.subject.contains(search_query)) |
            (User.grade.contains(search_query))
        ).all()
    else:
        all_users = User.query.all()
    return render_template('users.html', users=all_users)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        user = User.query.filter_by(email=email).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            return redirect(url_for('home'))
        else:
            flash('Invalid credentials', 'error')
    return render_template('login.html')

@app.route('/choose_subject', methods=['GET', 'POST'])
def choose_subject():
    if request.method == 'POST':
        subject = request.form.get('subject')
        if subject:
            user_id = current_user.id
            user = User.query.get(user_id)
            if user:
                user.subject = subject
                db.session.commit()
                return redirect(url_for('home'))
    return render_template('choose_subject.html')

@app.route('/mentoring/<int:user_id>', methods=['POST'])
@login_required
def mentoring(user_id):
    user = User.query.get_or_404(user_id)
    msg = Message('Mentoring Request', recipients=[user.email])
    return redirect(url_for('users'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)