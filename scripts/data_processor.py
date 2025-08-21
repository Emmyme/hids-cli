import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder, StandardScaler

class DataProcessor:
    def __init__(self):
        self.label_encoders = {}
        self.scaler = StandardScaler()
        
    def load_data(self, filepath):
        # Load data from csv file
        return pd.read_csv(filepath)
    
    def detect_attack_patterns(self, data):
        # Detect attack patterns
        patterns = []

        for _, row in data.iterrows():
            attack_type = "Unknown"
            confidence = "Low"

            # Brute Force Attack
            if (row['login_attempts'] > 5 and 
                row['failed_logins'] > 2 and 
                row['session_duration'] < 100):
                attack_type = "Brute Force"
                confidence = "High"

            # DDoS Attack
            elif (row['network_packet_size'] > 800 and 
                  row['protocol_type'] in ['UDP', 'ICMP'] and 
                  row['session_duration'] > 1000):
                attack_type = "DDoS"
                confidence = "High"
                
            # Credential Stuffing
            elif (row['failed_logins'] > 3 and 
                  row['ip_reputation_score'] < 0.3 and 
                  row['login_attempts'] > 3):
                attack_type = "Credential Stuffing"
                confidence = "Medium"
                
            # Session Hijacking
            elif (row['session_duration'] > 2000 and 
                  row['unusual_time_access'] == 1 and 
                  row['encryption_used'] == 'None'):
                attack_type = "Session Hijacking"
                confidence = "Medium"
                
            # Data Exfiltration
            elif (row['network_packet_size'] > 600 and 
                  row['session_duration'] > 1500 and 
                  row['browser_type'] == 'Unknown'):
                attack_type = "Data Exfiltration"
                confidence = "Medium"
            
            patterns.append({
                'attack_type': attack_type,
                'confidence': confidence,
                'risk_score': self.calculate_risk_score(row)
            })
            
        return pd.DataFrame(patterns)
    
    def calculate_risk_score(self, row):
        # Calculate the risk score based on different factors
        risk_score = 0
        
        # Network packet size
        if row['network_packet_size'] > 800:
            risk_score += 25
        elif row['network_packet_size'] > 600:
            risk_score += 15
        elif row['network_packet_size'] > 400:
            risk_score += 10
        
        # Failed logins
        risk_score += min(row['failed_logins'] * 5, 20)

        # IP reputation
        risk_score += int((1 - row['ip_reputation_score'] * 20))

        # Session duration
        if row['session_duration'] > 2000:
            risk_score += 15
        elif row['session_duration'] > 1000:
            risk_score += 10

        # Unusual time access
        risk_score += row['unusual_time_access'] * 10

        # Encryption
        if row['encryption_used'] == 'None':
            risk_score += 10

        return min(risk_score, 100)

    def preprocess_data(self, df):
        # Preprocess the data
        data = df.copy()

        data['risk_score'] = data.apply(self.calculate_risk_score, axis=1)
        data['high_packet_size'] = (data['network_packet_size'] > 600).astype(int)
        data['high_failed_logins'] = (data['failed_logins'] > 2).astype(int)
        data['low_ip_reputation'] = (data['ip_reputation_score'] < 0.3).astype(int)
        data['long_session'] = (data['session_duration'] > 1000).astype(int)
        
        categorical_cols = ['protocol_type', 'encryption_used', 'browser_type']
        for col in categorical_cols:
            if col in data.columns:
                le = LabelEncoder()
                data[col] = le.fit_transform(data[col].astype(str))
                self.label_encoders[col] = le
        
        # Separate features and target
        X = data.drop(['session_id', 'attack_detected'], axis=1)
        y = data['attack_detected']
        

        X_scaled = self.scaler.fit_transform(X)
        
        return X_scaled, y
    
    def split_data(self, X, y, test_size=0.2, random_state=42):
        # Split data into train and test sets
        return train_test_split(X, y, test_size=test_size, random_state=random_state)
    
    def get_threat_details(self, row):
        attack_patterns = self.detect_attack_patterns(pd.DataFrame([row]))
        pattern = attack_patterns.iloc[0]

        threat_details = {
            'attack_type': pattern['attack_type'],
            'confidence': pattern['confidence'],
            'risk_score': pattern['risk_score'],
            'timestamp': pd.Timestamp.now().strftime('%Y-%m-%d %H:%M:%S'),
            'indicators': self.get_threat_indicators(row)
        }

        return threat_details
    
    def get_threat_indicators(self, row):
        indicators = []

        if row['network_packet_size'] > 600:
            indicators.append(f"High network packet size: {row['network_packet_size']} bytes")
        if row['failed_logins'] > 2:
            indicators.append(f"Multiple failed logins: {row['failed_logins']}")
        if row['ip_reputation_score'] < 0.3:
            indicators.append(f"Low IP reputation: {row['ip_reputation_score']:.2f}")
        if row['session_duration'] > 1000:
            indicators.append(f"Long session duration: {row['session_duration']:.2f} seconds")
        if row['unusual_time_access'] == 1:
            indicators.append("Unusual access time")
        if row['encryption_used'] == 'None':
            indicators.append("No encryption used")

        return indicators
