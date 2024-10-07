import os
import requests

BASE_URL="https://api.polygon.io/vX/reference/financials?ticker={}&limit=10&apiKey={}"

def get_fundamentals_data(symbol:str) :
    api_key = os.environ.get('POLYGON_API_KEY')
    if not api_key : 
        raise ValueError("POLYGON_API_KEY is not set in environment variables") 
    
    url = BASE_URL.format(symbol,api_key)
    try : 
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        
        if 'results' not in data:
            print('Unexpected API response',data)
            raise ValueError("Invalid response format:'results' not found!")

        ttm_data = data['results'][0]
        return ttm_data
    except requests.RequestException as e:
        print(f"Error fetching stock fundamentals : {e}")
        raise ValueError(f"Failed to fetch fundamentals : {str(e)}")

NEWS_URL="https://finnhub.io/api/v1/company-news?symbol={}&from=2024-01-01&to=2024-09-01&token={}"
    
def get_news_data(symbol:str):
    api_key = os.environ.get('FINNHUB_API_KEY')
    if not api_key:
        raise ValueError("FINNHUB_API_KEY is not configured.")
    url = NEWS_URL.format(symbol,api_key)
    try : 
        response = requests.get(url)
        response.raise_for_status()
        data = response.json()
        news_data = data[:20]
        return news_data;
    except : 
        print(f"Error fetching stocks news")
        raise ValueError(f"Failed to fetch news")