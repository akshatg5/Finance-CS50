# have to create a similar endpoint as done for the us stocks to get the data for indian stocks

import os
import requests
from datetime import datetime,timedelta
from flask import Flask,jsonify
from functools import lru_cache
import yfinance as yf
import pandas as pd

ALPHAVANTAGE_API_KEY = os.getenv('ALPHAVANTAGE_API_KEY')
BASE_URL = "https://www.alphavantage.co/query?function=TIME_SERIES_DAILY&symbol={symbol}&outputsize=full&apikey={api_key}"

# simply edit and format the url to put in symbols along with api key to get the desired result
# def get_edited_url(symbol:str) : 
#     api_key = ALPHAVANTAGE_API_KEY
#     if not api_key:
#         print("Api Key is invalid")
#     return BASE_URL.format(symbol=symbol,api_key=api_key)

# #ohlcv
# class StockData : 
#     def __init__(self,date:str,open:float,high:float,low:float,close:float,volume:int) -> None:
#         self.date = date
#         self.open = open
#         self.high = high
#         self.low = low
#         self.close = close
#         self.volume = volume
        
        
# @lru_cache  # why tf do we do this???? Got it we can hold this for each day
# def get_indian_stock_graph(symbol:str) -> list[StockData] :
#     try :
#         response = requests.get(get_edited_url(symbol),headers={"Content-Type" : "application/json"})
#         response.raise_for_status()
#         data = response.json()

#         if "Error Message" in data :
#             raise ValueError(f"API Error : {data['Error Message']}")
#         if "Time Series (Daily)" not in data :
#             print("Unexpected API response error",data)
            
#         time_series = data['Time Series (Daily)']
#         today = datetime.now()
#         start_date = today - timedelta(days=100) # will start fetching data of the past 100 days
#         stock_data_array = []
#         for date,value in time_series.items():
#             date_obj = datetime.strptime(date,"%Y-%m-%d")
#             if start_date < date_obj <= today :
#                 stock_data = StockData(
#                     date = date,
#                     open = float(value["1. open"]),
#                     high = float(value["2. high"]),
#                     low = float(value["3. low"]),
#                     close = float(value["4. close"]),
#                     volume= int(value["5. volume"])
#                 )
#                 stock_data_array.append(stock_data)
                
#         if not stock_data_array:
#             raise ValueError("No data available for the specified date range.")
#         return sorted(stock_data_array,key=lambda x:datetime.strptime(x.date,"%Y-%m-%d"))
#     except requests.RequestException as e : 
#         print(f"Error fetching the stock data : {e}")
#         raise ValueError("Failed to fetch stokc data : {str(e)}")
#     except Exception as e:
#         print(f"Error processing stock data : {e}")
#         raise ValueError(f"Failed to process stock data : {str(e)}")

# def get_price_for_stock(symbol):
#     try : 
#         response = requests.get(get_edited_url(symbol),headers={"Content-Type" : "application/json"})
#         response.raise_for_status()
#         data = response.json()

#         if "Error Message" in data :
#             raise ValueError(f"API Error : {data['Error Message']}")
#         if "Time Series (Daily)" not in data :
#             print("Unexpected API response error",data)
#         time_series = data['Time Series (Daily)']
#         latest_date = max(time_series.keys())
#         latest_data = time_series[latest_date]
#         latest_price = latest_data['4. close']
#         return {
#             'symbol' : symbol,
#             'price' : latest_price,
#             'date' : latest_date
#         }
#     except requests.RequestException as e:
#         print(f"Error fetching the stock data: {e}")
#         raise ValueError(f"Failed to fetch stock data: {str(e)}")
#     except Exception as e:
#         print(f"Error processing stock data: {e}")
#         raise ValueError(f"Failed to process stock data: {str(e)}")
import yfinance as yf
from datetime import datetime, timedelta
from functools import lru_cache

class StockData:
    def __init__(self, date: str, open: float, high: float, low: float, close: float, volume: int) -> None:
        self.date = date
        self.open = open
        self.high = high
        self.low = low
        self.close = close
        self.volume = volume

def get_nse_symbol(symbol: str) -> str:
    """Convert symbol to NSE format for Yahoo Finance."""
    # Remove any existing suffixes
    symbol = symbol.split('.')[0]
    # Add .NS suffix if not present
    if not symbol.endswith('.NS'):
        return f"{symbol}.NS"
    return symbol

def is_valid_nse_symbol(symbol: str) -> bool:
    """Check if the symbol is valid by attempting to fetch its info."""
    try:
        ticker = yf.Ticker(get_nse_symbol(symbol))
        info = ticker.info
        return 'symbol' in info and info['symbol'] == get_nse_symbol(symbol)
    except:
        return False

@lru_cache
def get_indian_stock_graph(symbol: str) -> list[StockData]:
    try:
        symbol = get_nse_symbol(symbol)
        if not is_valid_nse_symbol(symbol):
            raise ValueError(f"Invalid NSE symbol: {symbol}")

        end_date = datetime.now()
        start_date = end_date - timedelta(days=100)
        
        stock = yf.Ticker(symbol)
        df = stock.history(start=start_date, end=end_date)

        stock_data_array = []
        for index, row in df.iterrows():
            stock_data = StockData(
                date=index.strftime('%Y-%m-%d'),
                open=float(row['Open']),
                high=float(row['High']),
                low=float(row['Low']),
                close=float(row['Close']),
                volume=int(row['Volume'])
            )
            stock_data_array.append(stock_data)

        if not stock_data_array:
            raise ValueError("No data available for the specified date range.")
        return sorted(stock_data_array, key=lambda x: datetime.strptime(x.date, "%Y-%m-%d"))
    except Exception as e:
        print(f"Error processing stock data: {e}")
        raise ValueError(f"Failed to process stock data: {str(e)}")

def get_price_for_stock(symbol: str):
    try:
        symbol = get_nse_symbol(symbol)
        if not is_valid_nse_symbol(symbol):
            raise ValueError(f"Invalid NSE symbol: {symbol}")

        stock = yf.Ticker(symbol)
        latest_data = stock.history(period="1d")

        if latest_data.empty:
            raise ValueError(f"No data available for symbol: {symbol}")

        latest_price = latest_data['Close'].iloc[-1]
        latest_date = latest_data.index[-1].strftime('%Y-%m-%d')

        return {
            'symbol': symbol,
            'price': str(latest_price),  # Convert to string to match original format
            'date': latest_date
        }
    except Exception as e:
        print(f"Error fetching the stock data: {e}")
        raise ValueError(f"Failed to fetch stock data: {str(e)}")
    
# Load the CSV file once during initialization
csv_path = os.path.join(os.path.dirname(__file__), 'EQUITY_L.csv')
df = pd.read_csv(csv_path)

def search_indian_stocks(query: str, limit: int = 10) -> list[dict]:
    try:
        mask = df['SYMBOL'].str.contains(query, case=False) | df['NAME OF COMPANY'].str.contains(query, case=False)
        results = df[mask].head(limit)
        stocks = [
            {
                'symbol': f"{row['SYMBOL']}.NS",
                'name': row['NAME OF COMPANY']
            }
            for _, row in results.iterrows()
        ]
        return stocks
    except Exception as e:
        print(f"Error searching for stocks: {e}")
        return []