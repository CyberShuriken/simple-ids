from flask import Flask, render_template, jsonify
from ids_engine import IDSEngine

app = Flask(__name__)
ids = IDSEngine()

@app.route('/')
def index():
    return render_template('dashboard.html', rules=ids.rules)

@app.route('/api/alerts')
def get_alerts():
    return jsonify(ids.get_alerts())

if __name__ == '__main__':
    print("Starting Simple IDS...")
    print("Note: Requires Administrator privileges to sniff packets.")
    
    ids.start()
    app.run(debug=True, port=5000)
