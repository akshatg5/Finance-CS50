from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

db = SQLAlchemy()

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=True)
    fullname = db.Column(db.String(200),nullable=True)
    phone = db.Column(db.String(20),unique=True,nullable=True)
    hash = db.Column(db.String(255), nullable=True)
    cash = db.Column(db.Float, default=10000.00,nullable=False)
    indiancash = db.Column(db.Float, default=10000.00,nullable=False)
    nationality = db.Column(db.String(100),nullable=True)
    email = db.Column(db.String(120),unique=True,nullable=True,default="")
    google_id = db.Column(db.String(255),unique=True,nullable=True,default="")
    
class Transaction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    ticker = db.Column(db.String(10), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    shares = db.Column(db.Integer, nullable=False)
    price = db.Column(db.Float, nullable=False)
    type = db.Column(db.String(4), nullable=False)
    time = db.Column(db.DateTime(timezone=True), default=datetime.utcnow)
    
class IndianStockTransactions(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer,db.ForeignKey('user.id'),nullable=False)
    ticker = db.Column(db.String(50),nullable=False)
    name = db.Column(db.String(100),nullable=False)
    shares = db.Column(db.Integer,nullable=False)
    price = db.Column(db.Float,nullable=False)
    type = db.Column(db.String(4),nullable=False)
    time = db.Column(db.DateTime(timezone=True),default=datetime.utcnow)