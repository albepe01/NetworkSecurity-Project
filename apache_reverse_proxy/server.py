from flask import Flask

app = Flask(__name__)

@app.route('/test', methods=['GET','POST'])
def test():
    return "Test OK", 200

@app.route('/hidden_test', methods=['GET','POST'])
def hidden_test():
    return "Hidden Test OK", 200

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)

