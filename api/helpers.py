import os
import requests
from dotenv import load_dotenv
from functools import lru_cache
import pandas as pd

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


csv_path = os.path.join(os.path.dirname(__file__), 'nasdaq_search.csv')
nasdaq_df = pd.read_csv(csv_path)
def search_us_stocks(query : str,limit : int = 10) -> list[dict] :
    try :
        all_tickers = nasdaq_df['Symbol'].tolist() 
        all_names = nasdaq_df['Name'].tolist()
        
        df = pd.DataFrame({'symbol' : all_tickers,'name' : all_names}) 

        # search for the matching query
        mask = df['symbol'].str.contains(query,case=False) | df['name'].str.contains(query,case=False)
        results = df[mask].head(limit)
        
        stocks = [
            {
            'symbol' : row['symbol'],
            'name' : row['name']
            }
            for _,row in results.iterrows()
        ]
        return stocks
    except Exception as e :
        print(f"Error searching for stocks : {e}")
        return [] 

