
# 🛡️ PhishGuard

## Machine Learning Based Phishing URL Detection

PhishGuard is a machine learning-based web application that detects whether a given URL is **Phishing** or **Legitimate**.

The system extracts lexical and structural features from the URL and uses a trained machine learning model to make the prediction.

## Features

- URL-based phishing detection
- 16 lexical and structural URL features
- Multiple machine learning models compared
- Random Forest selected as the best-performing model
- Streamlit-based user interface
- Probability-based prediction
- Online deployment using Streamlit and Cloudflare Tunnel

## Machine Learning Models

The following models were compared:

1. Logistic Regression
2. Decision Tree
3. Random Forest
4. Support Vector Machine (SVM)
5. XGBoost

### Best Model

Random Forest achieved the best overall performance on the test dataset.

| Metric | Score |
|---|---:|
| Accuracy | 99.9554% |
| Precision | 99.9866% |
| Recall | 99.8930% |
| F1-Score | 99.9398% |
| ROC-AUC | 0.999997 |

## URL Features

The model uses the following features:

- URL length
- IP address presence
- Dot count
- HTTPS flag
- URL entropy
- Token count
- Subdomain count
- Query parameter count
- TLD length
- Path length
- Hyphen in domain
- Number of digits
- TLD popularity
- Suspicious file extension
- Domain name length
- Percentage of numeric characters

## Project Structure

```text
PhishGuard/
│
├── app.py
├── phishguard_model.pkl
├── requirements.txt
└── README.md
