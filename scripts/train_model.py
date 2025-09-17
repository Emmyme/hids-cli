import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))

from scripts.data_processor import DataProcessor
from scripts.model import SecurityModel

def main():
    print("Training pre-trained model for HIDS CLI...")
    
    try:
        # Load and process data
        processor = DataProcessor()
        data = processor.load_data('data/cybersecurity_intrusion_data.csv')
        X, y = processor.preprocess_data(data)
        X_train, X_test, y_train, y_test = processor.split_data(X, y)
        
        # Train model
        model = SecurityModel()
        model.train(X_train, y_train)
        
        # Evaluate model
        accuracy = model.evaluate(X_test, y_test)
        
        # Save model
        model.save_model('models/pretrained_model.pkl', 
                        label_encoders=processor.label_encoders,
                        scaler=processor.scaler)
        
        print(f"Pre-trained model saved to: models/pretrained_model.pkl")
        print(f"Model accuracy: {accuracy:.4f}")
        print(" Model is ready for production use!")
        
    except Exception as e:
        print(f"Error training model: {str(e)}")
        sys.exit(1)

if __name__ == '__main__':
    main()
