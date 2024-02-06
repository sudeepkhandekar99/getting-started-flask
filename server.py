from flask import Flask

app = Flask(__name__)

@app.route('/')
def home():
    return "This is the root endpoint"

@app.route('/healthz', methods=['GET'])
def healthz():
    return "This is a healthz endpoint"

if (__name__ == "__main__"):
    app.run()