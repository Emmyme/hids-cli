import joblib
import pandas as pd
import os
import subprocess
import datetime
import sys
sys.path.append(os.path.join(os.path.dirname(__file__), '..', 'scripts'))

from scripts.data_processor import DataProcessor

class SecurityAnalyzer:
    # Security threat analyzer
    
    def __init__(self, model_path='models/pretrained_model.pkl'):
        self.model = None
        self.label_encoders = {}
        self.scaler = None
        self.processor = DataProcessor()
        self.load_model(model_path)
    
    def load_model(self, model_path):
        # Load the model
        if not os.path.exists(model_path):
            raise FileNotFoundError(f"Pre-trained model not found: {model_path}")
        
        model_data = joblib.load(model_path)
        self.model = model_data['model']
        self.label_encoders = model_data['label_encoders']
        self.scaler = model_data['scaler']
    
    def analyze_threat(self, row):
        try:
            processed_data = self._preprocess_single_record(row)
            
            prediction = self.model.predict(processed_data)[0]
            probability = self.model.predict_proba(processed_data)[0]
            
            threat_details = self.processor.get_threat_details(row)
            
            threat_details.update({
                'prediction': prediction,
                'probability': probability,
                'threat_status': "THREAT" if prediction == 1 else "NO THREAT"
            })
            
            return threat_details
        except Exception as e:
            print(f"Error in analyze_threat: {e}")
            raise e
    
    def read_system_data(self):
        system_data = []
        
        try:
            # Get network connections
            network_data = self._get_network_connections()
            
            # Get security events (if accessible)
            security_data = self._get_security_events()
            
            # Combine the data
            system_data = network_data + security_data
            
        except Exception as e:
            print(f"Error reading system data: {e}")
            
        return system_data
    
    def _get_network_connections(self):
        # Get network connection data
        connections = []
        
        try:
            # Use netstat to get connections
            result = subprocess.run(['netstat', '-an'], capture_output=True, text=True)
            lines = result.stdout.split('\n')
            
            # Parse netstat output
            for i, line in enumerate(lines[4:]):  # Skip header
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 4:
                        connections.append({
                            'session_id': f"NET_{i}",
                            'network_packet_size': 0,  # Default
                            'protocol_type': parts[0] if parts else 'TCP',
                            'login_attempts': 1,  # Default
                            'session_duration': 0,  # Default
                            'encryption_used': 'Unknown',  # Default
                            'ip_reputation_score': 0.5,  # Default
                            'failed_logins': 0,  # Default
                            'browser_type': 'System',  # Default
                            'unusual_time_access': self._is_unusual_time()
                        })
        except:
            pass
            
        return connections
    
    def _get_security_events(self):
        # Get security event data
        events = []
        
        try:
            # Try to get recent security events
            result = subprocess.run([
                'wevtutil', 'qe', 'Security', 
                '/q:"*[System[EventID=4625 or EventID=4624]]"', 
                '/c:10', '/f:csv'
            ], capture_output=True, text=True)
            
            if result.returncode == 0:
                # Parse CSV output
                lines = result.stdout.split('\n')
                for i, line in enumerate(lines[1:]): 
                    if line.strip():
                        events.append({
                            'session_id': f"SEC_{i}",
                            'network_packet_size': 0,  # Default
                            'protocol_type': 'LOCAL',  # Local security event
                            'login_attempts': 1,  # One event
                            'session_duration': 0,  # Default
                            'encryption_used': 'Unknown',  # Default
                            'ip_reputation_score': 0.5,  # Default
                            'failed_logins': 1 if '4625' in line else 0,  # Event 4625 = failed login
                            'browser_type': 'System',  # Default
                            'unusual_time_access': self._is_unusual_time()
                        })
        except:
            pass
            
        return events
    
    def _is_unusual_time(self):
        # Check if current time is unusual for activity
        current_hour = datetime.datetime.now().hour
        return 1 if current_hour < 6 or current_hour > 22 else 0
    
    def _preprocess_single_record(self, row):
        try:
            data = pd.DataFrame([row])
            
            # Calculate risk score
            data['risk_score'] = self.processor.calculate_risk_score(row)
            
            categorical_cols = ['protocol_type', 'encryption_used', 'browser_type']
            for col in categorical_cols:
                if col in data.columns and col in self.label_encoders:
                    try:
                        data[col] = self.label_encoders[col].transform(data[col].astype(str))
                    except:
                        data[col] = 0
            
            data['high_packet_size'] = (data['network_packet_size'] > 600).astype(int)
            data['high_failed_logins'] = (data['failed_logins'] > 2).astype(int)
            data['low_ip_reputation'] = (data['ip_reputation_score'] < 0.3).astype(int)
            data['long_session'] = (data['session_duration'] > 1000).astype(int)
            
            # Remove non-feature columns
            X = data.drop(['session_id'], axis=1, errors='ignore')
            
            # Scale using saved scaler
            X_scaled = self.scaler.transform(X)
            
            return X_scaled
        except Exception as e:
            print(f"Error in preprocessing: {e}")
            print(f"Row data: {row}")
            raise e
