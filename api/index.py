import os
from flask import Flask, jsonify, request
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from dotenv import load_dotenv
from flask_migrate import Migrate

from helpers import lookup, usd

load_dotenv()

app = Flask(__name__)
CORS(app)

DATABASE_URI = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

migrate = Migrate(app, db)

# JWT configuration
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET')
jwt = JWTManager(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    hash = db.Column(db.String(255), nullable=False)
    cash = db.Column(db.Float, default=10000.00)

class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ticker = db.Column(db.String(10), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    shares = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(4), nullable=False)
    time = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)


@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route("/", methods=["GET"])
def serverCheck():
    """Server check."""
    return jsonify("Server check")

@app.route("/api/portfolio")
@jwt_required()
def index():
    """Show portfolio of stocks"""
    user_id = get_jwt_identity()
    
    stocks = db.session.query(Transaction.ticker, Transaction.name, Transaction.price, 
                              db.func.sum(Transaction.shares).label('totalshares'))\
        .filter_by(user_id=user_id)\
        .group_by(Transaction.ticker, Transaction.name, Transaction.price)\
        .all()
    
    user = User.query.get(user_id)
    cash = user.cash
    total = cash

    stocks_list = []
    for stock in stocks:
        stock_dict = {
            'ticker': stock.ticker,
            'name': stock.name,
            'price': stock.price,
            'totalshares': stock.totalshares
        }
        total += stock.price * stock.totalshares
        stocks_list.append(stock_dict)

    return jsonify({"stocks": stocks_list, "cash": cash, "total": total})

@app.route("/api/balance", methods=["GET"])
@jwt_required()
def balance():
    """Get the current cash balance of the user"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    balance = user.cash
    return jsonify({"balance": balance})

@app.route("/api/buy", methods=["POST"])
@jwt_required()
def buy():
    """Buy shares of stock"""
    user_id = get_jwt_identity()
    symbol = request.json.get("symbol", "").upper()
    shares = request.json.get("shares", 0)
    
    if not symbol or shares <= 0:
        return jsonify({"error": "Invalid symbol or shares"}), 400
    
    stock = lookup(symbol)
    if not stock:
        return jsonify({"error": "Invalid stock symbol"}), 400

    user = User.query.get(user_id)
    total_price = stock['price'] * shares
    if total_price > user.cash:
        return jsonify({"error": "Insufficient Funds"}), 400
    
    user.cash -= total_price
    new_transaction = Transaction(user_id=user_id, ticker=symbol, name=stock['name'],
                                  shares=shares, price=stock['price'], type="BUY")
    db.session.add(new_transaction)
    db.session.commit()

    return jsonify({"message": f"{stock['name']} Purchased successfully"})

@app.route("/api/history")
@jwt_required()
def history():
    """Show history of transactions"""
    user_id = get_jwt_identity()
    transactions = Transaction.query.filter_by(user_id=user_id).all()
    return jsonify([{
        'type': t.type,
        'ticker': t.ticker,
        'price': t.price,
        'shares': t.shares,
        'time': t.time
    } for t in transactions])

@app.route("/api/login", methods=["POST"])
def login():
    """Log user in"""
    username = request.json.get("username", None)
    password = request.json.get("password", None)
    
    if not username or not password:
        return jsonify({"error": "Missing username or password"}), 401
    
    user = User.query.filter_by(username=username).first()
    if not user or not check_password_hash(user.hash, password):
        return jsonify({"error": "Invalid username or password!"}), 401
    
    access_token = create_access_token(identity=user.id)
    return jsonify(access_token=access_token)

@app.route("/api/quote", methods=["POST"])
def quote():
    """Get stock quote."""
    symbol = request.json.get("symbol", "").upper()
    if not symbol:
        return jsonify({"error": "Missing symbol"}), 400
    print("Looking up")
    stock_quote = lookup(symbol)
    if not stock_quote:
        return jsonify({"error": "Invalid symbol"}), 400
    
    return jsonify(stock_quote)

@app.route("/api/register", methods=["POST"])
def register():
    """Register user"""
    username = request.json.get("username")
    password = request.json.get("password")
    
    if not username or not password:
        return jsonify({"error": "Missing password or username."}), 401
    
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists, please sign in!"}), 400
    
    hashed_password = generate_password_hash(password)
    new_user = User(username=username, hash=hashed_password)
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully!"}), 201

@app.route("/api/sell", methods=["POST"])
@jwt_required()
def sell():
    """Sell shares of stock"""
    user_id = get_jwt_identity()
    symbol = request.json.get("symbol", "").upper()
    shares = request.json.get("shares", 0)
    
    if not symbol or shares <= 0:
        return jsonify({"error": "Invalid symbol or number of shares"}), 400
    
    user_shares = db.session.query(db.func.sum(Transaction.shares))\
        .filter_by(user_id=user_id, ticker=symbol).scalar()
    
    if shares > user_shares:
        return jsonify({"error": "Not enough shares"}), 400
    
    stock = lookup(symbol)
    if not stock:
        return jsonify({"error": "Invalid stock symbol"}), 400
    
    user = User.query.get(user_id)
    total_price = stock["price"] * shares
    user.cash += total_price
    
    new_transaction = Transaction(user_id=user_id, ticker=symbol, name=stock["name"],
                                  shares=-shares, price=stock["price"], type="SELL")
    db.session.add(new_transaction)
    db.session.commit()

    return jsonify({"message": "Stock sold successfully"})
