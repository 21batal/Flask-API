from flask import Flask, request, jsonify, send_file
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import pyotp, jwt, datetime
from functools import wraps
import qrcode
import io
import base64

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root@localhost/di'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = 'your_secret_key'

db = SQLAlchemy(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50), unique=True, nullable=False)
    password = db.Column(db.String(256), nullable=False)
    twofa_secret = db.Column(db.String(256), nullable=False)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True, autoincrement=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.String(255), nullable=True)
    price = db.Column(db.Numeric(10,2), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)

def token_required(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        token = request.headers.get('Authorization')
        if not token:
            return jsonify({'message': 'Token is missing'}), 403
        try:
            token = token.split()[1]
            data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=['HS256'])
        except:
            return jsonify({'message': 'Token is invalid'}), 403
        return f(*args, **kwargs)
    return decorated

@app.route('/')
def home():
    return jsonify({'message': 'Welcome to the API'})

@app.route('/favicon.ico')
def favicon():
    return '', 204

@app.route('/register', methods=['POST'])
def register_user():
    data = request.json
    username = data.get('username')
    password = data.get('password')
    if not username or not password:
        return jsonify({'message': 'Username and password required'}), 400
    
    if User.query.filter_by(username=username).first():
        return jsonify({'message': 'User already exists'}), 400
    
    hashed_password = generate_password_hash(password)
    twofa_secret = pyotp.random_base32()
    new_user = User(username=username, password=hashed_password, twofa_secret=twofa_secret)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User registered successfully'})

@app.route('/generate-2fa/<username>', methods=['GET'])
def generate_2fa(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404

    uri = pyotp.totp.TOTP(user.twofa_secret).provisioning_uri(
        name=username, issuer_name='YourAppName'
    )
    
    qr = qrcode.make(uri)
    img = io.BytesIO()
    qr.save(img, format='PNG')
    img.seek(0)
    
    qr_base64 = base64.b64encode(img.getvalue()).decode('utf-8')

    return jsonify({'qr_code': qr_base64})

@app.route('/verify-2fa/<username>', methods=['POST'])
def verify_2fa(username):
    user = User.query.filter_by(username=username).first()
    if not user:
        return jsonify({'message': 'User not found'}), 404
    
    user_code = request.json.get('code')
    totp = pyotp.TOTP(user.twofa_secret)
    if totp.verify(user_code):
        return jsonify({'message': '2FA verified successfully'})
    else:
        return jsonify({'message': 'Invalid or expired code'}), 401

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    user = User.query.filter_by(username=data.get('username')).first()
    if not user or not check_password_hash(user.password, data.get('password')):
        return jsonify({'message': 'Invalid credentials'}), 401
    
    token = jwt.encode({'user': user.username, 'exp': datetime.datetime.utcnow() + datetime.timedelta(hours=1)}, app.config['SECRET_KEY'], algorithm='HS256')
    return jsonify({'token': token})

@app.route('/add-product', methods=['POST'])
@token_required
def add_product():
    data = request.json
    new_product = Product(name=data['name'], description=data['description'], price=data['price'], quantity=data['quantity'])
    db.session.add(new_product)
    db.session.commit()
    return jsonify({'message': 'Product added successfully'})

@app.route('/products', methods=['GET'])
def get_products():
    products = Product.query.all()
    return jsonify([{'id': p.id, 'name': p.name, 'description': p.description, 'price': float(p.price), 'quantity': p.quantity} for p in products])

@app.route('/product/<int:id>', methods=['GET'])
def get_product(id):
    product = Product.query.get(id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    return jsonify({'id': product.id, 'name': product.name, 'description': product.description, 'price': float(product.price), 'quantity': product.quantity})

@app.route('/product/<int:id>', methods=['PUT'])
@token_required
def update_product(id):
    product = Product.query.get(id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    data = request.json
    product.name = data.get('name', product.name)
    product.description = data.get('description', product.description)
    product.price = data.get('price', product.price)
    product.quantity = data.get('quantity', product.quantity)
    db.session.commit()
    return jsonify({'message': 'Product updated successfully'})

@app.route('/product/<int:id>', methods=['DELETE'])
@token_required
def delete_product(id):
    product = Product.query.get(id)
    if not product:
        return jsonify({'message': 'Product not found'}), 404
    db.session.delete(product)
    db.session.commit()
    return jsonify({'message': 'Product deleted successfully'})

if __name__ == '__main__':
    with app.app_context():
        db.create_all()
    app.run(debug=True)
