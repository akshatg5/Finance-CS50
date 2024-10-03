import os
import requests
from datetime import datetime, timedelta
from flask import Flask, jsonify
from functools import lru_cache

BASE_URL = "https://api.polygon.io/v2/aggs/ticker/{}/range/1/day/{}/{}?adjusted=true&sort=asc&apiKey={}"

class StockData:
    def __init__(self, date, open, high, low, close, volume):
        self.date = date
        self.open = open
        self.high = high
        self.low = low
        self.close = close
        self.volume = volume

@lru_cache(maxsize=None)
def get_stock_data(symbol: str, from_date: str, to_date: str):
    api_key = os.environ.get('POLYGON_API_KEY')
    if not api_key:
        raise ValueError("POLYGON_API_KEY is not set in environment variables")

    url = BASE_URL.format(symbol, from_date, to_date, api_key)

    try:
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()

        if 'results' not in data:
            print("Unexpected API response:", data)
            raise ValueError("Invalid response format: 'results' not found")

        stock_data_list = []
        for item in data['results']:
            stock_data = StockData(
                date=datetime.fromtimestamp(item['t'] / 1000).strftime('%Y-%m-%d'),
                open=item['o'],
                high=item['h'],
                low=item['l'],
                close=item['c'],
                volume=item['v']
            )
            stock_data_list.append(stock_data)

        if not stock_data_list:
            raise ValueError("No data available for the specified date range")

        return stock_data_list

    except requests.RequestException as e:
        print(f"Error fetching stock data: {e}")
        raise ValueError(f"Failed to fetch stock data: {str(e)}")