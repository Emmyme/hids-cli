import joblib
from sklearn.ensemble import RandomForestClassifier
import pandas as pd
from sklearn.metrics import classification_report, accuracy_score
import os

class SecurityModel:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.is_trained = False
        self.feature_importance = None
        
    def train(self, X_train, y_train):
        # Train the security threat detection model
        print("Training security threat detection model...")
        self.model.fit(X_train, y_train)
        self.is_trained = True

        self.feature_importance = pd.DataFrame({
            'feature': X_train.columns if hasattr(X_train, 'columns') else [f'feature_{i}' for i in range(X_train.shape[1])],
            'importance': self.model.feature_importances_
        }).sort_values(by='importance', ascending=False)

        print("Model training completed!")

    def get_feature_importance(self):
        if not self.is_trained:
            raise ValueError("Model must be trained before getting feature importance")
        return self.feature_importance
    
    def predict_with_confidence(self, X):
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        
        predictions = self.predict(X)
        probabilities = self.predict_proba(X)
        confidence = probabilities.max(axis=1)
        
        return predictions, confidence, probabilities
        
    def predict(self, X):
        # Make predictions on new data
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        return self.model.predict(X)
    
    def predict_proba(self, X):
        # Get prediction probabilities
        if not self.is_trained:
            raise ValueError("Model must be trained before making predictions")
        return self.model.predict_proba(X)
    
    def evaluate(self, X_test, y_test):
        # Evaluate model performance
        if not self.is_trained:
            raise ValueError("Model must be trained before evaluation")
        
        y_pred = self.predict(X_test)
        accuracy = accuracy_score(y_test, y_pred)
        
        print(f"Model Accuracy: {accuracy:.4f}")
        print("\nClassification Report:")
        print(classification_report(y_test, y_pred))
        
        return accuracy
    
    def save_model(self, filepath, label_encoders=None, scaler=None):
        # Save the trained model with preprocessing components
        if not self.is_trained:
            raise ValueError("Model must be trained before saving")
        
        os.makedirs(os.path.dirname(filepath), exist_ok=True)

        model_data = {
            'model': self.model,
            'label_encoders': label_encoders or {},
            'scaler': scaler
        }
        
        joblib.dump(model_data, filepath)
        print(f"Model and preprocessing components saved to {filepath}")
    
    def load_model(self, filepath):
        # Load a trained model
        if os.path.exists(filepath):
            self.model = joblib.load(filepath)
            self.is_trained = True
            print(f"Model loaded from {filepath}")
        else:
            raise FileNotFoundError(f"Model file not found: {filepath}")
