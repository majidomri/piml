from flask import Flask, render_template, redirect, url_for, flash, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf import FlaskForm
# from wtforms import StringField, PasswordField, SubmitField # Keep this line if RegistrationForm is defined before LoginForm
from wtforms.validators import DataRequired, Length, EqualTo, ValidationError
import os

# Initialize Flask app
app = Flask(__name__)
app.config['SECRET_KEY'] = os.urandom(24) # Important for session management
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

# Initialize extensions
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login' # Redirect to 'login' view if @login_required fails

# --- Database Models (Will be defined in the next step) ---
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

import json # For storing variable_values
from datetime import datetime # For created_at timestamp

class SavedPrompt(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    base_prompt_template = db.Column(db.Text, nullable=False)
    custom_name = db.Column(db.String(150), nullable=True)
    variable_values = db.Column(db.Text, nullable=False) # Store as JSON string
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('saved_prompts', lazy='dynamic')) # Changed to lazy='dynamic'

    def __repr__(self):
        return f"<SavedPrompt {self.id} by User {self.user_id} - Name: {self.custom_name or 'Untitled'}>"

    def get_variable_values_dict(self):
        """Returns the variable_values as a Python dictionary."""
        return json.loads(self.variable_values)

    def set_variable_values_dict(self, values_dict):
        """Sets the variable_values from a Python dictionary."""
        self.variable_values = json.dumps(values_dict)

class UserVariableSet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    set_name = db.Column(db.String(100), nullable=False)
    variable_values = db.Column(db.Text, nullable=False)  # Store as JSON string: {"slot_name": "value", ...}
    created_at = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)

    user = db.relationship('User', backref=db.backref('variable_sets', lazy='dynamic'))

    def __repr__(self):
        return f"<UserVariableSet {self.id} '{self.set_name}' by User {self.user_id}>"

    def get_variables_dict(self):
        return json.loads(self.variable_values)

    def set_variables_dict(self, variables_dict):
        self.variable_values = json.dumps(variables_dict)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

from wtforms import StringField, PasswordField, SubmitField, BooleanField
# --- Forms ---
class RegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')

    def validate_username(self, username):
        user = User.query.filter_by(username=username.data).first()
        if user:
            raise ValidationError('That username is taken. Please choose a different one.')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=4, max=25)])
    password = PasswordField('Password', validators=[DataRequired()])
    remember = BooleanField('Remember Me')
    submit = SubmitField('Login')

# --- Routes (Will be expanded in later steps) ---
@app.route('/')
@login_required
def index():
    # Now @login_required handles the redirect if not authenticated
    return render_template('index.html', user=current_user)

@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        hashed_password = generate_password_hash(form.password.data)
        user = User(username=form.username.data, password_hash=hashed_password)
        db.session.add(user)
        db.session.commit()
        flash('Your account has been created! You are now able to log in.', 'success')
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user, remember=form.remember.data)
            flash('Logged in successfully!', 'success')
            next_page = request.args.get('next')
            return redirect(next_page) if next_page else redirect(url_for('index'))
        else:
            flash('Login Unsuccessful. Please check username and password', 'danger')
    return render_template('login.html', title='Login', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    flash('You have been logged out.', 'success')
    return redirect(url_for('login'))

@app.route('/profile')
@login_required
def profile():
    user_saved_prompts = SavedPrompt.query.filter_by(user_id=current_user.id).order_by(SavedPrompt.created_at.desc()).all()
    user_variable_sets = UserVariableSet.query.filter_by(user_id=current_user.id).order_by(UserVariableSet.set_name).all()
    return render_template('profile.html', user=current_user, saved_prompts=user_saved_prompts, variable_sets=user_variable_sets)

@app.route('/api/save_prompt', methods=['POST'])
@login_required
def api_save_prompt():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid data"}), 400

    base_prompt_template = data.get('base_prompt_template')
    variable_values_dict = data.get('variable_values')
    custom_name = data.get('custom_name')

    if not base_prompt_template or variable_values_dict is None: # variable_values can be an empty dict
        return jsonify({"error": "Missing required fields"}), 400

    try:
        saved_prompt = SavedPrompt(
            user_id=current_user.id,
            base_prompt_template=base_prompt_template,
            custom_name=custom_name
        )
        saved_prompt.set_variable_values_dict(variable_values_dict) # Use helper to store as JSON
        db.session.add(saved_prompt)
        db.session.commit()
        return jsonify({"success": True, "message": "Prompt saved!", "prompt_id": saved_prompt.id}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error saving prompt: {e}")
        return jsonify({"error": "Could not save prompt due to an internal error."}), 500

@app.route('/api/save_variable_set', methods=['POST'])
@login_required
def api_save_variable_set():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Invalid data"}), 400

    set_name = data.get('set_name')
    variable_values_dict = data.get('variable_values')

    if not set_name or not variable_values_dict: # variable_values_dict should not be empty
        return jsonify({"error": "Missing set_name or variable_values"}), 400

    if not isinstance(variable_values_dict, dict) or not variable_values_dict:
        return jsonify({"error": "variable_values must be a non-empty dictionary"}), 400

    try:
        variable_set = UserVariableSet(
            user_id=current_user.id,
            set_name=set_name
        )
        variable_set.set_variables_dict(variable_values_dict)
        db.session.add(variable_set)
        db.session.commit()
        return jsonify({"success": True, "message": "Variable set saved!", "set_id": variable_set.id}), 201
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error saving variable set: {e}")
        return jsonify({"error": "Could not save variable set due to an internal error."}), 500

@app.route('/api/delete_variable_set/<int:set_id>', methods=['POST']) # Using POST for simplicity, could be DELETE
@login_required
def api_delete_variable_set(set_id):
    variable_set = UserVariableSet.query.get_or_404(set_id)
    if variable_set.user_id != current_user.id:
        return jsonify({"error": "Unauthorized"}), 403 # Forbidden

    try:
        db.session.delete(variable_set)
        db.session.commit()
        return jsonify({"success": True, "message": "Variable set deleted."}), 200
    except Exception as e:
        db.session.rollback()
        app.logger.error(f"Error deleting variable set {set_id}: {e}")
        return jsonify({"error": "Could not delete variable set due to an internal error."}), 500

@app.route('/hello')
def hello():
    return "Hello from Flask!"

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
