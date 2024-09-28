import os
import requests
from dotenv import load_dotenv

load_dotenv()

FINNHUB_API_KEY = os.getenv('FINNHUB_API_KEY')

def lookup(symbol):
    """Look up stock quote for symbol using Finnhub."""
    symbol = symbol.upper()
    url = f"https://finnhub.io/api/v1/quote?symbol={symbol}&token={FINNHUB_API_KEY}"
    
    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        if "error" in data:
            return None
        
        price = round(data["c"], 2)  # Current price
        return {
            "name": symbol,
            "price": price,
            "symbol": symbol
        }
    
    except (requests.RequestException, ValueError, KeyError, IndexError):
        return None

def usd(value):
    """Format value as USD."""
    return f"${value:,.2f}"