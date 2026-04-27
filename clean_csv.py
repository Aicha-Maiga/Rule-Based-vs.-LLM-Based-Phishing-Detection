"""
Aicha Maiga
CIS 602-01
Spring 2026
"""

import pandas as pd

def clean_my_csv():
    try:
        # Load the file
        df = pd.read_csv("Phishing_Email.csv", encoding="latin-1", low_memory=False)
        print("Cleaning...")
        
        # Grab only the text and type columns
        df = df.iloc[:, -2:] 
        df.columns = ["Email Text", "Email Type"]
        
        # Drop empty rows and save
        df = df.dropna(subset=["Email Text"])
        df.to_csv("Phishing_Email_Cleaned.csv", index=False, encoding="utf-8")
        
        print("Success! Created 'Phishing_Email_Cleaned.csv'")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    clean_my_csv()