from flask import Flask, request, jsonify
import joblib
from sklearn.feature_extraction.text import TfidfVectorizer
import requests
import re

app = Flask(__name__)

# Load the saved grid search object
loaded_grid_search = joblib.load('gs_clf.pkl')

# Extract the best estimator (including the TfidfVectorizer)
best_estimator = loaded_grid_search.best_estimator_

# Extract the TfidfVectorizer from the best estimator
tokenizer = best_estimator.named_steps['tfidf']

# Preprocess function using the loaded tokenizer
def preprocess_sms_text(text):
    # Tokenize the text and remove stopwords
    text_tokens = tokenizer.transform([text])
    preprocessed_text = ' '.join(text_tokens.toarray().astype(str))

    return preprocessed_text

@app.route("/receive-sms", methods=["POST"])
def receive_sms():
    try:
        # Get JSON data from the request
        sms_data = request.get_json()
        header = sms_data.get("header", "")
        body = sms_data.get("Body", "")

        # Use regex to extract URLs from the message body
        url_pattern = r'https?://\S+'
        extracted_urls = re.findall(url_pattern, body)

        if not body:
            return jsonify({"error": "Empty SMS body"}), 400

        # Initialize variables to store classification results
        ham_or_spam = "Unknown"
        url_malicious = "Unknown"

        # Check if the message is ham or spam
        predicted_label = best_estimator.predict([body])

        if predicted_label[0] == 'ham':
            ham_or_spam = "Ham"
        elif predicted_label[0] == 'spam':
            ham_or_spam = "Spam"

        if extracted_urls:
            # If URLs are found, check the first one for malicious content
            url = extracted_urls[0]
            result_virus = virustotal(url)

            if "The URL is not malicious" in result_virus:
                url_malicious = "Not Malicious"
            else:
                url_malicious = "Malicious"

        # Construct the response JSON
        response = {
            "message_classification": {
                "ham_or_spam": ham_or_spam,
                "url_malicious": url_malicious
            },
            "message_body": body
        }

        return jsonify(response), 200

    except Exception as e:
        return jsonify({"error": str(e)}), 500

def virustotal(url):
    # Your virustotal code here
    payload = {"url": url}
    virus_url = "https://www.virustotal.com/api/v3/urls"
    headers = {
        "accept": "application/json",
        "x-apikey": "c2ad5bb192d4f6ad664c6bf363ef5db75d76d81856d9868a0b18f8ce7196cfd5",
        "content-type": "application/x-www-form-urlencoded",
    }

    response = requests.post(virus_url, data=payload, headers=headers)

    if response.status_code == 200:
        analysis_data = response.json()

        if "data" in analysis_data:
            analysis_id = analysis_data["data"]["id"]
            analysis_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"

            while True:
                analysis_response = requests.get(analysis_url, headers=headers)
                analysis_result = analysis_response.json()
                analysis_status = analysis_result.get("data", {}).get("attributes", {}).get("status")

                if analysis_status == "completed":
                    verdict = analysis_result.get("data", {}).get("attributes", {}).get("stats", {}).get("malicious", 0)

                    if verdict > 0:
                        return "The URL is malicious."
                    else:
                        return "The URL is not malicious."
                elif analysis_status == "queued" or analysis_status == "inprogress":
                    return "Analysis is still in progress. Checking again in a moment..."
                else:
                    return f"Analysis status: {analysis_status}"
    else:
        return f"Failed to retrieve analysis results. Status code: {response.status_code}"

if __name__ == "__main__":
 app.run(host="0.0.0.0", port=5000, debug=True)

