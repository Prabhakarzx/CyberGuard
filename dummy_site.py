# dummy_site.py (self made Vulnerable Website)
from flask import Flask, request

app = Flask(__name__)

@app.route('/')
def home():
    return '''
        <h1>Local Test Bank</h1>
        <p>Search User Database:</p>
        <form action="/search" method="GET">
            <input type="text" name="query" placeholder="Enter username">
            <input type="submit" value="Search">
        </form>
    '''

@app.route('/search')
def search():
    query = request.args.get('query', '')
    # self made SQL Injection vulnerability
    if "'" in query or '"' in query:
        return f"Fatal error: You have an error in your SQL syntax near '{query}' at line 1"

    # self made XSS vulnerability
    if "<script>" in query:
        return f"Results for: {query}" # Script reflected without sanitization
        
    return f"No results found for user: {query}"

if __name__ == '__main__':
    print("Dummy Vulnerable Site is running at: http://127.0.0.1:5000")
    app.run(port=5000)