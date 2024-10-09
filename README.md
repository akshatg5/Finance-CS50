# Stock Portfolio Backend

This is the backend server for a stock portfolio management application. It provides APIs for user authentication, stock trading, portfolio management, and stock analysis using AI.

## Features

- User registration and authentication
- Real-time stock quotes
- Buy and sell stocks
- View portfolio and transaction history
- AI-powered stock analysis using Google's Gemini API
- Database integration for persistent storage

## Technologies Used

- Python 3.8+
- Flask
- Google Generative AI (Gemini)
- PostgreSQL

## Prerequisites

Before you begin, ensure you have met the following requirements:

- Python 3.8 or higher installed
- pip (Python package manager)
- PostgreSQL database

## Setting Up Locally

Follow these steps to set up the project locally:

1. Clone the repository:
   ```
   git clone https://github.com/akshatg5/Finance-CS50
   ```

2. Create a virtual environment (recommended):
   ```
   python -m venv venv
   source venv/bin/activate  # On Windows, use `venv\Scripts\activate`
   ```

3. Install the required dependencies:
   ```
   pip install -r requirements.txt
   ```

4. Set up the environment variables:
   Create a `.env` file in the root directory with the following content:
   ```
   JWT_SECRET=your_jwt_secret_here
   FINNHUB_API_KEY=your_finnhub_api_key_here
   DATABASE_URI=your_database_uri_here
   POLYGON_API_KEY=your_polygon_api_key_here
   GEMINI_API_KEY=your_gemini_api_key_here
   ```
   Replace the placeholder values with your actual API keys and database URI.

5. Initialize the database:
   ```
   flask db init
   flask db migrate
   flask db upgrade
   ```

6. Run the application:
   ```
   flask --app api/index.py run
   ```

The server should now be running on http://127.0.0.1:5000

## Contributing

Contributions to the Litekite Backend are welcome. Please follow these steps:

1. Fork the repository
2. Create a new branch (`git checkout -b feature/featureName`)
3. Make your changes
4. Commit your changes (`git commit -m 'feat/fix:Add/fix this feature'`)
5. Push to the branch (`git push origin feature/featureName`)
6. Open a Pull Request


## Contact

If you have any questions or feedback, please reach out to [Me](https://x.com/AkshatGirdhar2).
