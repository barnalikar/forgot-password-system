from flask import Flask, request, jsonify, render_template
from flask_sqlalchemy import SQLAlchemy
from datetime import date
import random
import string
import bcrypt

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True)
    phone = db.Column(db.String(15), unique=True)
    password = db.Column(db.String(120))
    last_reset_request = db.Column(db.Date)

def generate_password(length=8):
    letters = string.ascii_uppercase
    return ''.join(random.choice(letters) for _ in range(length))

@app.route('/')
def home():
    return "Forgot Password System Running 🚀"
@app.route('/login-page')
def login_page():
    return render_template('login.html')

@app.route('/forgot-page')
def forgot_page():
    return render_template('forgot_password.html')

@app.route('/forgot-password', methods=['POST'])
def forgot_password():
    data = request.json
    email = data.get('email')
    phone = data.get('phone')
    
    user = None

    if email:
        user = User.query.filter_by(email=email).first()
    elif phone:
        user = User.query.filter_by(phone=phone).first()

    if not user:
        return jsonify({"message": "User not found"}), 404

    today = date.today()

    if user.last_reset_request == today:
        return jsonify({
            "message": "You can use this option only one time per day."
        }), 403

    new_password = generate_password()

    hashed = bcrypt.hashpw(new_password.encode('utf-8'), bcrypt.gensalt())
    user.password = hashed.decode('utf-8')
    user.last_reset_request = today
    db.session.commit()

    return jsonify({
        "message": "Password reset successful",
        "new_password": new_password
    })

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    email = data.get('email')
    password = data.get('password')

    user = User.query.filter_by(email=email).first()

    if not user:
        return jsonify({"message": "User not found"}), 404

    stored_password = user.password

    if not stored_password.startswith("$2b$"):
        return jsonify({"message": "Password not properly hashed. Reset required."}), 500

    if not bcrypt.checkpw(password.encode('utf-8'), stored_password.encode('utf-8')):
        return jsonify({"message": "Incorrect password"}), 401
    return jsonify({
        "message": "Login successful",
        "user": {
            "email": user.email,
            "phone": user.phone
        }
    })

if __name__ == '__main__':
    with app.app_context():
        db.create_all()

        if not User.query.filter_by(email="test@gmail.com").first():
            hashed = bcrypt.hashpw("oldpassword".encode('utf-8'), bcrypt.gensalt())

            user = User(
                email="test@gmail.com",
                phone="1234567890",
                password=hashed.decode('utf-8')
            )
            db.session.add(user)
            db.session.commit()

    app.run(debug=True)
