# Rule-Based vs. LLM-Based Phishing Detection: A Comparative Evaluation of Accuracy and Output Interpretability

# Overview
This project compares a rule-based phishing detection system with an LLM-based system using Gemini.

The goal is to evaluate both classification performance (accuracy, precision, recall) and output interpretability for non-technical users.

# Features
- Rule-based phishing detection using predefined indicators
- LLM-based detection using Gemini API
- Evaluation metrics: Accuracy, Precision, Recall
- Output Interpretability Score (OIS)

# Dataset
- 30 email samples (phishing and legitimate)
- Used for controlled evaluation

# Set Up
To run these codes, you will need an API key for the LLM-based system. For security reasons, the API key is not included in this repository.
The rule-based system will still work without the API key, but the LLM-based system requires the API key to run.

1. Get your own API key (Google Gemini API key used in this project).
2. Create a folder named .stremlit and  a new file named secret.toml. 
3. Store your API key inside that file using GEMINI_KEY = "actul_key"


