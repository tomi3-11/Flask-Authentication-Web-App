from flask import Flask, render_template, request, redirect, url_for, flash
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from authlib.integrations.flask_client import OAuth
import json
import os
from dotenv import load_dotenv

# Loading environmental variables
load_dotenv()

app = Flask(__name__)
app.config['SECRET_KEY'] = 'My-Secret-Key_Here'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Configuring flask-login
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'

# Configuring OAuth
oauth = OAuth(app)
google = oauth.register(
    name='google',
    client_id=os.environ.get('GOOGLE_CLIENT_ID'),
    client_secret=os.environ.get('GOOGLE_CLIENT_SECRET'),
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile'
    }
)

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    google_id = db.Column(db.String(200), unique=True, nullable=True)  # stores Google "sub"
    username = db.Column(db.String(100), unique=True)
    email = db.Column(db.String(120), unique=True, nullable=True)
    password_hash = db.Column(db.String(100), nullable=True)
    picture = db.Column(db.String(200))
    
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
        
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)
    
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# Home page.
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/auth_login')
def auth_login():
    if current_user.is_authenticated:
        return redirect(url_for('profile'))
    
    # Generate the authorization URL
    redirect_uri = url_for('auth', _external=True)
    return google.authorize_redirect(redirect_uri)

@app.route('/auth')
def auth():
    # Get the token from google
    token = google.authorize_access_token()
    
    # Get user info from google
    user_info = google.parse_id_token(token)

    
    user = User.query.filter_by(google_id=user_info['sub']).first()
    # Create or get user
    if not user:
        user = User(
            google_id=user_info['sub'],
            username=user_info.get('name') or user_info['email'].split('@')[0],
            email=user_info['email'],
            picture=user_info.get('picture')
        )
        db.session.add(user)
        db.session.commit()
        
    # Login the user
    login_user(user)
    return redirect(url_for('profile'))



@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')
        remember = True if request.form.get('remember') else False
        
        user = User.query.filter_by(username=username).first()
        
        if not user or not user.check_password(password):
            flash('Please check your login details and try again.')
            return redirect(url_for('login'))
        
        login_user(user, remember=remember)
        return redirect(url_for('profile'))
    
    return render_template('login.html')


@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        
        user = User.query.filter(
            (User.username == username) | (User.email == email)
        ).first()
        
        if user:
            flash('Username already exists')
            return redirect(url_for('register'))
        
        new_user = User(username=username, email=email)
        new_user.set_password(password)
        
        db.session.add(new_user)
        db.session.commit()
        
        return redirect(url_for('login'))
    
    return render_template('register.html')


@app.route('/profile')
@login_required
def profile():
    return render_template(
        'profile.html', 
        name=current_user.username,
        email=current_user.email,
        picture=current_user.picture
    )


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))


if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)