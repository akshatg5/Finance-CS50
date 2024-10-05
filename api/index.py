import os
from flask import Flask, jsonify, request,render_template
from flask_sqlalchemy import SQLAlchemy
from flask_cors import CORS
from flask_jwt_extended import JWTManager, jwt_required, create_access_token, get_jwt_identity
from werkzeug.security import check_password_hash, generate_password_hash
from datetime import datetime
from dotenv import load_dotenv
from flask_migrate import Migrate
from flask_admin import Admin
from flask_admin.contrib.sqla import ModelView
from datetime import datetime, timedelta
from sqlalchemy import func
import google.generativeai as genai
import json
import requests
import psycopg2

from .models import db,User,Transaction
from .helpers import lookup,usd
from .stock import get_stock_data

load_dotenv()

app = Flask(__name__)
CORS(app)

genai.configure(api_key=os.getenv("GEMINI_API_KEY"))

DATABASE_URI = os.getenv('DATABASE_URI')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db.init_app(app)

migrate = Migrate(app, db)
# JWT configuration
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET')
jwt = JWTManager(app)

admin = Admin(app,name='DBView',template_mode='bootstrap3')
admin.add_view(ModelView(User,db.session))
admin.add_view(ModelView(Transaction,db.session))

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

@app.route('/dbview')
def db_view() :
    users = User.query.all()
    transactions = Transaction.query.all()
    return render_template('db_view.html',users=users,transactions=transactions)

@app.route("/", methods=["GET"])
def serverCheck():
    """Server check."""
    return jsonify("Server check")

@app.route("/api/portfolio")
@jwt_required()
def index():
    """Show portfolio of stocks"""
    user_id = get_jwt_identity()
    
    stocks = db.session.query(
        Transaction.ticker,
        Transaction.name,
        db.func.sum(Transaction.shares).label('totalshares'),
        db.func.sum(Transaction.shares * Transaction.price).label('total_cost')
    ).filter_by(user_id=user_id)\
        .group_by(Transaction.ticker,Transaction.name)\
            .having(db.func.sum(Transaction.shares) > 0)\
                .all()
    
    user = User.query.get(user_id)
    cash = user.cash
    total = cash

    stocks_list = []
    for stock in stocks:
        current_price = lookup(stock.ticker)['price'] if lookup(stock.ticker) else 0
        avg_purchase_price = stock.total_cost / stock.totalshares if stock.totalshares > 0 else 0
        current_value = current_price * stock.totalshares
        stock_dict = {
            'ticker': stock.ticker,
            'name': stock.name,
            'current_price': current_price,
            'avg_purcase_price' : avg_purchase_price,
            'totalshares': stock.totalshares,
            'current_value': current_value
        }
        total += current_value
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

@app.route("/api/currentstocks",methods=["GET"])
@jwt_required()
def currentStocks() :
    user_id = get_jwt_identity()
    holdings = db.session.query(
        Transaction.ticker,
        Transaction.name,
        func.sum(Transaction.shares).label('total_shares')
    ).filter(Transaction.user_id == user_id).group_by(Transaction.ticker,Transaction.name).having(func.sum(Transaction.shares) > 0 ).all()
    result = []
    for holding in holdings : 
        result.append({
            "ticker" : holding.ticker,
            "name" : holding.name,
            "total_shares" : holding.total_shares
        })
        
    return jsonify(result)
        
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

@app.route("/api/profile",methods=["GET"])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    profile = User.query.get(user_id)
    username = profile.username
    cash = profile.cash
    nationality = profile.nationality
    return jsonify({"username" : username,"cash":cash,"nationality" : nationality})

@app.route('/api/selectnation',methods=["POST"])
@jwt_required()
def selectNation() : 
    user_id = get_jwt_identity()
    nationality = request.json.get("nation")
    if not nationality:
        return jsonify({"error" : "Nationality not provided"}),400
    if nationality not in ["USA", "India"]:
        return jsonify({"error": "Invalid nationality. Must be 'USA' or 'India'"}), 400

    user = User.query.get(user_id)
    if not user : 
        return jsonify({"error" : "Invalid User"}),404
    user.nationality = nationality
    db.session.commit()
    return jsonify({"message" : "Nationality added","nationality" : nationality}),200
        

@app.route('/api/stock_data/<symbol>',methods=["GET"])
@jwt_required()
def stock_data(symbol):
    try:
        to_date = datetime.now().strftime('%Y-%m-%d')
        from_date = (datetime.now() - timedelta(days=100)).strftime('%Y-%m-%d')

        data = get_stock_data(symbol, from_date, to_date)
        return jsonify([vars(item) for item in data])
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    
from flask import jsonify, request
from flask_jwt_extended import jwt_required, get_jwt_identity
import json
import google.generativeai as genai
import re

@app.route('/api/analyze', methods=["POST"])
@jwt_required()
def analyze_stock():
    user_id = get_jwt_identity()
    data = request.json
    symbol = data.get("symbol", "").upper()
    shares = data.get("shares")
    avg_price = data.get("avg_price")
    ltp = data.get("ltp")
    
    if not all([symbol, shares, avg_price, ltp]):
        return jsonify({"error": "Missing requirements"}), 400

    prompt = f"""You are a long term capital market financial advisor.
    Follow this format for the response : {{ "pros": {{"1": "Point 1", "2": "Point 2"}}, "cons": {{"1": "Point 1", "2": "Point 2"}}, "suggestion": "Your suggestion about how to approach buying and selling shares of {symbol} in the current market scenario." }} and make sure the response is always in this format, no need to incldue any markdown, title enhancements,bold styling,ASCII characters in the resposne. Normal respnonse in the above mentioned format.
    The user has {shares} shares of {symbol} at an average price of ${avg_price}, currently trading at ${ltp}. Given the current dynamics of the company, the industry, the socio-economic situations, the way this industry is growing and how the stock has performed in the last few years, is this a good investment or not? Provide 2 pros and 2 cons in a JSON format: . Do not include any markdown formatting or code blocks in your response.
    1. Ensure this is in a json response. 
    2. Fetch the latest new headlines for the {symbol} and then form the suggestions.
    """
    
    try:
        model = genai.GenerativeModel('models/gemini-pro')
        response = model.generate_content(prompt)
        
        # Remove any code block formatting, leading/trailing whitespace, and non-ASCII characters
        json_string = re.sub(r'^```[\s\S]*\n|\n```$', '', response.text.strip())
        json_string = re.sub(r'[^\x00-\x7F]+', '', json_string)
        
        # Parse the JSON
        analysis = json.loads(json_string)
        
        return jsonify(analysis), 200
    except json.JSONDecodeError as e:
        # If JSON parsing fails, attempt to extract JSON from the response
        match = re.search(r'\{.*\}', json_string, re.DOTALL)
        if match:
            try:
                analysis = json.loads(match.group())
                return jsonify(analysis), 200
            except:
                pass
        
        # If extraction fails, return a formatted JSON response with the raw text
        return jsonify({
            "pros": {
                "1": "Unable to parse AI response",
                "2": "Please check the raw response for details"
            },
            "cons": {
                "1": "AI response format error",
                "2": "Manual intervention may be required"
            },
            "suggestion": "The AI response could not be properly parsed. Please review the raw response and consider regenerating the analysis.",
            "raw_response": json_string
        }), 200
    except Exception as e:
        return jsonify({
            "pros": {
                "1": "Error occurred during analysis",
                "2": "System is still operational"
            },
            "cons": {
                "1": "Unable to provide accurate analysis at this time",
                "2": "Manual intervention may be required"
            },
            "suggestion": "An unexpected error occurred. Please try again later or contact support if the issue persists.",
            "error": str(e)
        }), 200
    
