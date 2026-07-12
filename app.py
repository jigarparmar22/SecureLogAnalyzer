from flask import Flask

app = Flask(__name__)

@app.route("/")
def home():
    return """
    <h1>Secure Log Analyzer</h1>
    <p>Project setup completed successfully!</p>
    """

if __name__ == "__main__":
    app.run(debug=True)