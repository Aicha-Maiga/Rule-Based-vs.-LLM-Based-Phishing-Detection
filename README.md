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
The dataset is a publicly available dataset found on Kaggle: https://www.kaggle.com/datasets/subhajournal/phishingemails
Use clean_csv.py to remove the first column 

# Set Up
To run these codes, you will need an API key for the LLM-based system. For security reasons, the API key is not included in this repository.
The rule-based system will still work without the API key, but the LLM-based system requires the API key to run.

1. Get your own API key (Google Gemini API key used in this project).
2. Create a folder named .stremlit and  a new file named secret.toml. 
3. Store your API key inside that file using GEMINI_KEY = "actual_key"

## Containerization

This project includes a Dockerfile so the application can be run inside a Docker container.

### Run with Docker

Build the image:

docker build -t phishing-detection-app .

Run the container:

docker run -p 8501:8501 phishing-detection-app

Then open:

http://localhost:8501

Note: The LLM-based system still requires a personal Gemini API key, which is not included in this repository for security reasons.
