from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from config import Config
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField
from wtforms.validators import DataRequired, Length, EqualTo
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.config.from_object(Config)
db = SQLAlchemy(app)

# --- Flask-Login setup ---
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"


# --- Database Models ---
class User(UserMixin, db.Model):  # for authentication
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Item(db.Model):  # Item CRUD
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(200), nullable=True)

    def __repr__(self):
        return f"<Item {self.name}>"


class AppUser(db.Model):  # User CRUD
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)


# --- Forms ---
class RegisterForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired(), Length(min=3, max=100)])
    password = PasswordField("Password", validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField("Confirm Password", validators=[DataRequired(), EqualTo("password")])
    submit = SubmitField("Register")


class LoginForm(FlaskForm):
    username = StringField("Username", validators=[DataRequired()])
    password = PasswordField("Password", validators=[DataRequired()])
    submit = SubmitField("Login")


class ItemForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(max=100)])
    description = StringField("Description", validators=[Length(max=200)])
    submit = SubmitField("Save")


class AppUserForm(FlaskForm):
    name = StringField("Name", validators=[DataRequired(), Length(max=100)])
    email = StringField("Email", validators=[DataRequired(), Length(max=120)])
    submit = SubmitField("Save")


# --- Flask-Login user loader ---
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))


# ======================
# Routes
# ======================

@app.route("/")
@login_required
def index():
    items = Item.query.all()
    return render_template("index.html", items=items)

@app.route("/dashboard")
@login_required
def dashboard():
    total_items = Item.query.count()
    total_users = User.query.count()
    return render_template("dashboard.html", total_items=total_items, total_users=total_users)


# --- Item CRUD ---
@app.route("/create", methods=["GET", "POST"])
@login_required
def create():
    form = ItemForm()
    if form.validate_on_submit():
        new_item = Item(name=form.name.data, description=form.description.data)
        db.session.add(new_item)
        db.session.commit()
        flash("Item created successfully!", "success")
        return redirect(url_for("index"))
    return render_template("create.html", form=form)


@app.route("/update/<int:id>", methods=["GET", "POST"])
@login_required
def update(id):
    item = Item.query.get_or_404(id)
    form = ItemForm(obj=item)
    if form.validate_on_submit():
        item.name = form.name.data
        item.description = form.description.data
        db.session.commit()
        flash("Item updated successfully!", "info")
        return redirect(url_for("index"))
    return render_template("update.html", form=form, item=item)


@app.route("/delete/<int:id>")
@login_required
def delete(id):
    item = Item.query.get_or_404(id)
    db.session.delete(item)
    db.session.commit()
    flash("Item deleted!", "danger")
    return redirect(url_for("index"))


# --- User CRUD ---
@app.route("/users")
@login_required
def users():
    users = AppUser.query.all()
    return render_template("users.html", users=users)


@app.route("/user/create", methods=["GET", "POST"])
@login_required
def create_user():
    form = AppUserForm()
    if form.validate_on_submit():
        new_user = AppUser(name=form.name.data, email=form.email.data)
        db.session.add(new_user)
        db.session.commit()
        flash("User created successfully!", "success")
        return redirect(url_for("users"))
    return render_template("create_user.html", form=form)


@app.route("/user/update/<int:id>", methods=["GET", "POST"])
@login_required
def update_user(id):
    user = AppUser.query.get_or_404(id)
    form = AppUserForm(obj=user)
    if form.validate_on_submit():
        user.name = form.name.data
        user.email = form.email.data
        db.session.commit()
        flash("User updated successfully!", "info")
        return redirect(url_for("users"))
    return render_template("update_user.html", form=form, user=user)


@app.route("/user/delete/<int:id>")
@login_required
def delete_user(id):
    user = AppUser.query.get_or_404(id)
    db.session.delete(user)
    db.session.commit()
    flash("User deleted!", "danger")
    return redirect(url_for("users"))


# --- Auth ---
@app.route("/register", methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        if User.query.filter_by(username=form.username.data).first():
            flash("Username already exists!", "danger")
        else:
            user = User(username=form.username.data)
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            flash("Registration successful! Please login.", "success")
            return redirect(url_for("login"))
    return render_template("register.html", form=form)


@app.route("/login", methods=["GET", "POST"])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            flash("Login successful!", "success")
            return redirect(url_for("index"))
        else:
            flash("Invalid username or password", "danger")
    return render_template("login.html", form=form)


@app.route("/logout")
@login_required
def logout():
    logout_user()
    flash("You have been logged out.", "info")
    return redirect(url_for("login"))


# --- Run ---
if __name__ == "__main__":
    app.run(debug=True)   
