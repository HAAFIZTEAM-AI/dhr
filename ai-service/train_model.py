import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
import joblib
import os

def train_model(dataset_path='data/pakistani_scams_dataset.csv'):
    if not os.path.exists(dataset_path):
        print(f"Dataset not found at {dataset_path}. Skipping training.")
        return
    df = pd.read_csv(dataset_path)
    pipeline = Pipeline([
        ('tfidf', TfidfVectorizer(max_features=10000, ngram_range=(1,2), sublinear_tf=True)),
        ('clf', LogisticRegression(max_iter=1000, class_weight='balanced'))
    ])
    pipeline.fit(df['text'], df['label'])
    os.makedirs('models', exist_ok=True)
    joblib.dump(pipeline, 'models/scam_detector.pkl')
    print("Model trained and saved.")

if __name__ == '__main__':
    train_model()