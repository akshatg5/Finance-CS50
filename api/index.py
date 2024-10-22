import os
from flask import Flask, jsonify, request,render_template,Response,url_for,redirect,session
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
from functools import wraps
from authlib.integrations.flask_client import OAuth
import secrets
import requests
import psycopg2
import json

from models import db,User,Transaction,IndianStockTransactions
from helpers import lookup,usd
from stock import get_stock_data
from fundamentals import get_fundamentals_data,get_news_data
from indianstocks import get_indian_stock_graph,get_price_for_stock,search_indian_stocks

load_dotenv()

app = Flask(__name__)
FRONTEND_URL = os.getenv('FRONTEND_URL')
CORS(app, resources={r"/api/*": {"origins": FRONTEND_URL }}, supports_credentials=True)
DATABASE_URI = os.getenv('DATABASE_URI')
GOOGLE_CLIENT_ID = os.getenv('GOOGLE_CLIENT_ID')
GOOGLE_CLIENT_SECRET = os.getenv('GOOGLE_CLIENT_SECRET')
SECRET_KEY = os.getenv('SECRET_KEY')
app.config['SQLALCHEMY_DATABASE_URI'] = DATABASE_URI
app.config['GOOGLE_CLIENT_ID'] = GOOGLE_CLIENT_ID
app.config['GOOGLE_CLIENT_SECRET'] = GOOGLE_CLIENT_SECRET
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['SECRET_KEY'] = SECRET_KEY
app.config['SESSION_COOKIE_SECURE'] = True
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'None'

db.init_app(app)

migrate = Migrate(app, db)
# JWT configuration
app.config["JWT_SECRET_KEY"] = os.getenv('JWT_SECRET')
jwt = JWTManager(app)
oauth = OAuth(app)

ADMIN_USERNAME = os.getenv('ADMIN_USERNAME',"admin")
ADMIN_PASSWORD = os.getenv('ADMIN_PASSWORD',"password")

admin = Admin(app,name='DBView',template_mode='bootstrap3')
admin.add_view(ModelView(User,db.session))
admin.add_view(ModelView(Transaction,db.session))

google = oauth.register(
    name='google',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_kwargs={
        'scope': 'openid email profile',
        'prompt': 'select_account'
    }
)

@app.after_request
def after_request(response):
    """Ensure responses aren't cached"""
    response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
    response.headers["Expires"] = 0
    response.headers["Pragma"] = "no-cache"
    return response

def check_auth(username,password):
    return username == ADMIN_USERNAME and password == ADMIN_PASSWORD

def authenticate():
    return Response(
        'Could not verify your access level for that URL.\n'
        'You have to login with proper credentials', 401,
        {'WWW-Authenticate': 'Basic realm="Login Required"'}
    )
    
def requires_auth(f) :
    @wraps(f)
    def decorated(*args,**kwargs) :
        auth = request.authorization
        if not auth or not check_auth(auth.username,auth.password):
            return authenticate()
        return f(*args,**kwargs)
    return decorated

@app.route('/dbview')
@requires_auth
def db_view() :
    users = User.query.all()
    transactions = Transaction.query.all()
    indiantransactions = IndianStockTransactions.query.all()
    return render_template('db_view.html',users=users,transactions=transactions,indiantransactions=indiantransactions)

@app.route("/", methods=["GET"])
def serverCheck():
    """Server check."""
    return jsonify("Server check")

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

    
@app.route("/api/register", methods=["POST"])
def register():
    """Register user"""
    username = request.json.get("username")
    password = request.json.get("password")
    fullname = request.json.get("fullname")
    phone = request.json.get("phone")
    email = request.json.get("email")
    nationality = request.json.get("nationality")
   
    
    if not username or not password:
        return jsonify({"error": "Missing password or username."}), 401
   
    if User.query.filter_by(username=username).first():
        return jsonify({"error": "Username already exists, please sign in!"}), 400
   
    if email and User.query.filter_by(email=email).first():
        return jsonify({"error": "Email already exists, please sign in!"}), 400
   
    if phone and User.query.filter_by(phone=phone).first():
        return jsonify({"error": "Phone number already exists, please sign in!"}), 400
   
    hashed_password = generate_password_hash(password)
    new_user = User(
        username=username, 
        hash=hashed_password,
        fullname=fullname,
        phone=phone,
        email=email,
        nationality=nationality
    )
    db.session.add(new_user)
    db.session.commit()

    return jsonify({"message": "User registered successfully!"}), 201

@app.route('/api/auth/google')
def google_auth():
    try:
        # Generate and store a random state
        state = secrets.token_urlsafe(16)
        session['oauth_state'] = state
        redirect_uri = url_for('google_callback', _external=True)
        # Get the URL as a string instead of Response object
        auth_url = google.authorize_redirect(redirect_uri, state=state).location
        return jsonify({"auth_url": auth_url})
    except Exception as e:
        print(f"Error in google_auth: {str(e)}")
        return jsonify({"error": "Failed to generate authentication URL"}), 500
    
@app.route('/api/auth/google/callback')
def google_callback():
    try:
        # Verify the state
        stored_state = session.pop('oauth_state', None)
        print(f"Stored state: {stored_state}")
        print(f"Received state: {request.args.get('state')}")
        
        if request.args.get('state') != stored_state:
            raise ValueError("Invalid state parameter")

        token = google.authorize_access_token()
        userinfo = token.get('userinfo')
        if userinfo is None:
            # Fallback to manual userinfo request if not in token
            resp = google.get('userinfo')
            userinfo = resp.json()

        # Use sub as the unique identifier
        google_id = userinfo.get('sub')
        if not google_id:
            raise ValueError("No user ID received from Google")

        user = User.query.filter_by(google_id=google_id).first()
        if not user:
            user = User(
                username=userinfo['email'],
                email=userinfo['email'],
                google_id=google_id,
                fullname=userinfo.get('name'),
                nationality=None
            )
            db.session.add(user)
            db.session.commit()
        
        # Create JWT with expiration
        expires = timedelta(hours=24)
        access_token = create_access_token(
            identity=user.id,
            expires_delta=expires
        )
        
        frontend_url = "http://localhost:5173/login"
        return redirect(f"{frontend_url}?token={access_token}")
    except Exception as e:
        print(f"Error in google_callback: {str(e)}")
        print(f"Full error details: {repr(e)}")
        frontend_url = "http://localhost:5173/login"
        return redirect(f"{frontend_url}?error=1")

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

@app.route("/api/indianportfolio", methods=["GET"])
@jwt_required()
def indianPortfolio():
    """Indian portfolio"""
    user_id = get_jwt_identity()
    stocks = db.session.query(
        IndianStockTransactions.ticker,
        IndianStockTransactions.name,
        db.func.sum(IndianStockTransactions.shares).label('totalIndianShares'),
        db.func.sum(IndianStockTransactions.shares * IndianStockTransactions.price).label('total_indian_cost')  
    ).filter_by(user_id=user_id)\
        .group_by(IndianStockTransactions.ticker, IndianStockTransactions.name)\
        .having(db.func.sum(IndianStockTransactions.shares) > 0)\
        .all()
                
    user = User.query.get(user_id)
    indiancash = float(user.indiancash)
    total = indiancash
    
    stock_list = []
    for stock in stocks:
        price_info = get_price_for_stock(stock.ticker)
        if price_info and 'price' in price_info:
            try:
                current_price = float(price_info['price'])
            except ValueError:
                # If the price is still a string with repeated values, take the first occurrence
                current_price = float(price_info['price'].split()[0])
        else:
            current_price = 0.0
        
        totalIndianShares = float(stock.totalIndianShares)
        avg_purchase_price = float(stock.total_indian_cost) / totalIndianShares if totalIndianShares > 0 else 0
        current_value = current_price * totalIndianShares
        
        stock_dict = {
            'ticker': stock.ticker,
            'name': stock.name,
            'current_price': current_price,
            'avg_purchase_price': avg_purchase_price,
            'totalShares': totalIndianShares,
            'current_value': current_value
        }
        total += current_value
        stock_list.append(stock_dict)
        
    return jsonify({"stocks": stock_list, "cash": indiancash, "total": total})

@app.route("/api/balance", methods=["GET"])
@jwt_required()
def balance():
    """Get the current cash balance of the user"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    balance = user.cash
    return jsonify({"balance": balance})

@app.route("/api/indianbalance", methods=["GET"])
@jwt_required()
def indianbalance():
    """Get the current cash balance of the user"""
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    balance = user.indiancash
    return jsonify({"indianbalance": balance})

@app.route('/api/editbalances',methods=["POST"])
@jwt_required()
def edit_balance() :
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user :
        return jsonify({"error" : "User not found!"}),404
    
    data = request.json
    updates = {}

    if 'cash'  in data : 
        try :
            cash_to_add = float(data['cash'])
            if cash_to_add < 0:
                return jsonify({"error" : "Balance cannot be negative"})
            user.cash += cash_to_add
            updates['US Balance Added'] = cash_to_add
            updates['US Balance'] = user.cash
        except ValueError as e :
            return jsonify({"error" : str(e)}),400
        
    if 'indiancash' in data : 
        try :
            indiancash_toadd = float(data['indiancash'])
            if indiancash_toadd < 0:
                return jsonify({"error" : "Balance cannot be negative"}),400
            user.indiancash += indiancash_toadd
            updates['Indian Balance added'] = indiancash_toadd
            updates['New Indian Balance'] = user.indiancash 
        except ValueError as e : 
            return jsonify({"error" : str(e)}),400
    
    if not updates :
        return jsonify({"error" : "No Valid balance updates provided!"}),400
        
    try : 
        db.session.commit()
        return jsonify(updates),200
    except Exception as e :
        db.session.rollback()
        return jsonify({"error" : "An error occured while updating the balance!"})    
        
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

@app.route("/api/buyindianstock",methods=["POST"])
@jwt_required()
def buy_indian_stock():
    user_id = get_jwt_identity()
    symbol = request.json.get("symbol","").upper()
    shares = request.json.get("shares",0)
    
    if not symbol or shares <= 0:
        return jsonify({"error" : "Invalid symbol or shares"}),400
    stock = get_price_for_stock(symbol)
    if not stock:
        return jsonify({"Error" : "Invalid stock symbol"}),400
    user = User.query.get(user_id)
    total_price = float(stock['price']) * float(shares)
    if (total_price) > user.indiancash :
        return jsonify({"error" : "Insufficient Funds"}),400
    user.indiancash -= total_price
    new_transaction = IndianStockTransactions(user_id=user_id,ticker=symbol.split('.')[0],name=stock['symbol'].split('.')[0],
                                                shares=shares,price=stock['price'],type="BUY")
    db.session.add(new_transaction)
    db.session.commit()
    return jsonify({"message": f"{stock['symbol']} Purchase Successful!"})
    
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
    
@app.route("/api/indianstockhistory")
@jwt_required()
def indianstockhistory():
    """Show history of transactions"""
    user_id = get_jwt_identity()
    transactions = IndianStockTransactions.query.filter_by(user_id=user_id).all()
    return jsonify([{
        'type': t.type,
        'ticker': t.ticker,
        'price': t.price,
        'shares': t.shares,
        'time': t.time
    } for t in transactions])

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

@app.route("/api/indianquote",methods=["POST"])
def indianquote():
    symbol = request.json.get("symbol","")
    if not symbol :
        return jsonify({"error" : "Missing Symbol"}),400
    stock_qote = get_price_for_stock(symbol)
    if not stock_qote:
        return jsonify({"error" : "Invalid symbol"}),400
    return jsonify(stock_qote)

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

@app.route("/api/currentindianstocks",methods=["GET"])
@jwt_required()
def currentIndianStocks() :
    user_id = get_jwt_identity()
    holdings = db.session.query(
        IndianStockTransactions.ticker,
        IndianStockTransactions.name,
        func.sum(IndianStockTransactions.shares).label('total_shares')
    ).filter(IndianStockTransactions.user_id == user_id).group_by(IndianStockTransactions.ticker,IndianStockTransactions.name).having(func.sum(IndianStockTransactions.shares) > 0 ).all()
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

@app.route('/api/sellindianstock',methods=['POST'])
@jwt_required()
def sell_indian_stock():
    user_id = get_jwt_identity()
    symbol = request.json.get("symbol", "")
    shares = request.json.get("shares", 0)
    
    if not symbol or shares <= 0:
        return jsonify({"error": "Invalid symbol or number of shares"}), 400
    
    user_shares = db.session.query(db.func.sum(IndianStockTransactions.shares))\
        .filter_by(user_id=user_id, ticker=symbol).scalar() or 0
    if shares > user_shares:
        return jsonify({"error": "Not enough shares"}), 400
    
    stock = get_price_for_stock(symbol)
    if not stock:
        return jsonify({"error": "Invalid stock symbol"}), 400
    
    user = User.query.get(user_id)
    
    # Ensure price is a float and round to 2 decimal places
    price = round(float(stock["price"]), 2)
    total_price = round(price * shares, 2)
    
    # Update user's cash
    user.cash = round(user.cash + total_price, 2)
    
    new_transaction = IndianStockTransactions(
        user_id=user_id,
        ticker=symbol.split('.')[0],
        name=stock["symbol"].split('.')[0],
        shares=-shares,
        price=price,
        type="SELL"
    )
    db.session.add(new_transaction)
    db.session.commit()
    
    return jsonify({"message": f"{stock['symbol']} Sold Successfully"})

@app.route("/api/profile",methods=["GET"])
@jwt_required()
def profile():
    user_id = get_jwt_identity()
    profile = User.query.get(user_id)
    username = profile.username
    cash = profile.cash
    nationality = profile.nationality
    indiancash = profile.indiancash
    return jsonify({"username" : username,"cash":cash,"nationality" : nationality,"indiancash" : indiancash})

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
    
@app.route('/api/indian_stock_data/<symbol>',methods=["GET"])
@jwt_required()
def indian_stock_data(symbol):
    try : 
        data = get_indian_stock_graph(symbol)
        return jsonify([vars(item) for item in data])
    except ValueError as e:
        return jsonify({"error" : str(e)}),400
    
@app.route('/api/fundamentals/<symbol>',methods=["GET"])
@jwt_required()
def get_fundamentals(symbol) :
    try :
        data = get_fundamentals_data(symbol)
        return jsonify(data)
    except ValueError as e : 
        return jsonify({"error" : str(e)}),400
    
@app.route('/api/news/<symbol>',methods=["GET"])
@jwt_required()
def get_news(symbol):
    try : 
        data = get_news_data(symbol)
        return jsonify(data)
    except ValueError as e : 
         return jsonify({"error" : str(e)}),400
    
@app.route('/api/indiansearch',methods=["GET"])
@jwt_required()
def search_stocks() :
    query = request.args.get('q','')
    limit = request.args.get('limit',10,type=int)
    if not query:
        return jsonify({"error" : "Search query is required"}),400
    results = search_indian_stocks(query,limit)
    return jsonify(results)