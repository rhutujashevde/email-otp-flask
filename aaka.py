
import random
from flask import Flask, render_template, redirect, url_for, session
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm 
from wtforms import StringField, PasswordField, BooleanField, IntegerField
from wtforms.validators import InputRequired, Email, Length, NumberRange
from flask_sqlalchemy  import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_mail import Mail, Message


app = Flask(__name__)
app.config['SECRET_KEY']='@####'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS']=True
app.config['SQLALCHEMY_DATABASE_URI'] = ''

app.config.update(
    DEBUG=True,
    #EMAIL SETTINGS
    MAIL_SERVER='smtp.gmail.com',
    MAIL_PORT=465,
    MAIL_USE_SSL=True,
    MAIL_USERNAME = 'projectSARmail@gmail.com',
    MAIL_PASSWORD = '#######'
    )

mail = Mail(app)
bootstrap = Bootstrap(app)
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


class Users(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(15), unique=True)
    email = db.Column(db.String(50))
    password = db.Column(db.String(80))

@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(int(user_id))

class LoginForm(FlaskForm):
    username = StringField('username', validators=[InputRequired(), Length(min=3, max=12)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    remember = BooleanField('remember me')

class RegisterForm(FlaskForm):
    email = StringField('email', validators=[InputRequired(), Email(message='Invalid email'), Length(max=50)])
    username = StringField('username', validators=[InputRequired(), Length(min=3, max=12)])
    password = PasswordField('password', validators=[InputRequired(), Length(min=8, max=80)])
    # mobile=IntegerField('mobile', validators=[InputRequired()])

class VerifyForm(FlaskForm):
    otp = IntegerField('otp', validators=[InputRequired()])

@app.route('/')
def homepage():
    return render_template('homepage.html')

@app.route('/index')
def index():
    random_number = random.randint(1000, 9998)
    return render_template('index.html', random_number=random_number)

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    form = RegisterForm()

    if form.validate_on_submit():
        email=form.email.data
        session['email'] = email
        username=form.username.data
        session['username'] = username
        password=form.password.data
        session['password'] = password               
        random_number = random.randint(1000, 9999)
        session['random_number'] = random_number
        msg = Message('otp',
        sender="projectSARmail@gmail.com",
        recipients=[email])
        msg.body = username+',\n'+' your otp is '+str(random_number)           
        mail.send(msg)
        return redirect(url_for('verify'))
        #return '<h1>' + form.username.data + ' ' + form.email.data + ' ' + form.password.data + '</h1>'

    return render_template('signup.html', form=form)

@app.route('/verify', methods=['GET', 'POST'])
def verify():
    form = VerifyForm()

    email= session['email']
    password= session['password']
    username= session['username']
    random_number= session['random_number']
    if form.validate_on_submit():
        print('validated form')
        if form.otp.data==random_number:
            hashed_password = generate_password_hash(password, method='sha256')
            new_user = Users(username=username, email=email, password=hashed_password)
            db.session.add(new_user)
            db.session.commit()
            return '<h1>New user has been created!</h1>'
        else:
            return '<h1>galat otp!</h1>'    
    return render_template('verify.html', form=form) 


@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()

    if form.validate_on_submit():
        user = Users.query.filter_by(username=form.username.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                if form.password.data=='adminpass' :
                    return '<h1>admin login</h1>'+'\n'+'<h1><a href="/logout">Logout</a></h1>'
                else:    
                    login_user(user, remember=form.remember.data)
                    return '<h1>Logged in!</h1>'+'\n'+'<h1><a href="/logout">Logout</a></h1>'
                #elif 
        return '<h1>Invalid username or password</h1>'
        #return '<h1>' + form.username.data + ' ' + form.password.data + '</h1>'

    return render_template('login.html', form=form)

@app.route('/showuser')
def showuser():
    users = Users.query.order_by(Users.username.desc()).all()
  
    return render_template('showuser.html', users=users)    
    
# @app.route('/dashboard')
# @login_required
# def dashboard():
#     return render_template('dashboard.html', name=current_user.username)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('homepage'))

db.create_all()

if __name__ == '__main__':
    app.run(port=1000,debug=True)
