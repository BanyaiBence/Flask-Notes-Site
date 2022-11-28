from flask import Blueprint, render_template, request, flash, redirect, url_for
from .models import User
from werkzeug.security import generate_password_hash, check_password_hash
from . import db
from flask_login import login_user, login_required, logout_user, current_user

auth = Blueprint("auth", __name__)

@auth.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()
        if user:
            if check_password_hash(user.password, password):
                flash("Logged in successfully!", category="success")
                login_user(user, remember=True)
                return redirect(url_for("views.home"))
            else:
                flash("Incorrect password! Try again!", category="error")
        else:
            flash("Email does not exist!", category="error")
    return render_template("login.html", user=current_user)

@auth.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("auth.login"))

@auth.route("/sign-up", methods=["GET", "POST"])
def sign_up():
    if request.method == "POST":
        #if the form have been submitted, is has to be a POST request
        email = request.form.get("email")
        firstName = request.form.get("firstName")
        password1 = request.form.get("password1")
        password2 = request.form.get("password2")

        user = User.query.filter_by(email=email).first()

        if user:
            #email already exist
            flash("Email already exist!", category="error")
        elif len(email) <4 or "@" not in email:
            #invalid email address
            flash("Invalid email address!", category="error")
        elif len(firstName) <5:
            #name is too short
            flash("Name should be greater than 4 characters!", category="error")
        elif len(password1) < 8:
            #password is too short
            flash("Password must be at least 7 characters!", category="error")
        elif password1 != password2:
            #passwordss aren't matching
            flash("Passwords don't match!", category="error")
        else:
            #add user to the database
            new_user = User(email=email, 
                            firstName=firstName, 
                            password=generate_password_hash(password1, method="sha256"))
            db.session.add(new_user)
            db.session.commit()
            flash("Account created!", category="success")
            login_user(new_user, remember=True)
            return redirect(url_for("views.home"))

    return render_template("sign-up.html", user=current_user)


