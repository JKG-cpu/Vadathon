from flask import Flask, render_template

App = Flask(__name__)

@App.route("/")
def home():
    return render_template("index.html")

@App.route("/login")
def login():
    return render_template("login.html")