from flask import Flask

app = Flask(__name__)

@app.route('/test', methods=['POST'])
def test():
    return "Test OK\n", 200

@app.route('/hidden_test', methods=['POST'])
def hidden_test():
    return "Hidden Test OK\n", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
