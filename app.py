from flask import Flask, request, jsonify, render_template
import joblib
import pandas as pd
from urllib.parse import urlparse

app = Flask(__name__)  # Correct here

model = joblib.load('phishing_model.pkl')

def extract_features_from_url(url):
    features = {
        'url_length': len(url),
        'has_ip': 1 if urlparse(url).hostname and urlparse(url).hostname.replace('.', '').isdigit() else 0,
        'count_https': url.count('https'),
        'count_http': url.count('http'),
        'count_www': url.count('www'),
        'count_dot': url.count('.'),
        'count_at': url.count('@'),
        'count_hyphen': url.count('-'),
        'count_slash': url.count('/'),
        'count_question': url.count('?'),
        'count_equal': url.count('=')
    }
    return pd.DataFrame([features])

@app.route('/')
def home():
    return render_template('main.html')

@app.route('/check_url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url')
    if not url:
        return jsonify({'error': 'No URL provided'}), 400

    features = extract_features_from_url(url)
    prediction = model.predict(features)[0]
    label = "SAFE - You can use it" if prediction == 0 else "PHISHING - Don't use it"

    return jsonify({'result': label})

if __name__ == '__main__':  # Correct here too
    app.run(debug=True)
