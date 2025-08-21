import click
import os
import pandas as pd
from src.analyzer import SecurityAnalyzer

@click.group()
def cli():
    # HIDS CLI - Security Threat Detection Tool
    pass

@cli.command()
@click.option('--model-path', default='models/pretrained_model.pkl',
              help='Path to trained model')
@click.option('--input-file', required=True, help='Path to input CSV file for prediction')
def predict(model_path, input_file):
    # Make predictions
    try:
        # Load analyzer 
        analyzer = SecurityAnalyzer(model_path)
        
        # Load and validate input data
        data = pd.read_csv(input_file)
        
        # Simple validation
        required_columns = [
            'network_packet_size', 'protocol_type', 'login_attempts',
            'session_duration', 'encryption_used', 'ip_reputation_score',
            'failed_logins', 'browser_type', 'unusual_time_access'
        ]
        
        missing_cols = [col for col in required_columns if col not in data.columns]
        if missing_cols:
            click.echo(f"❌ Missing required columns: {missing_cols}", err=True)
            return
        
        click.echo(" Analyzing security threats...")
        
        for i, (_, row) in enumerate(data.iterrows()):
            # Analyze threat
            result = analyzer.analyze_threat(row)
            
            click.echo(f"\n📊 Analysis for Record {i+1}:")
            click.echo(f"   Session ID: {row['session_id']}")
            click.echo(f"   Attack Type: {result['attack_type']}")
            click.echo(f"   Confidence: {result['confidence']}")
            click.echo(f"   Risk Score: {result['risk_score']}/100")
            click.echo(f"   Timestamp: {result['timestamp']}")
            
            if result['indicators']:
                click.echo("   🚨 Threat Indicators:")
                for indicator in result['indicators']:
                    click.echo(f"      • {indicator}")
            
            # Show prediction
            if result['threat_status'] == 'THREAT':
                click.echo("   🚨 SECURITY THREAT DETECTED!")
                click.echo(f"   Confidence: {max(result['probability']) * 100:.2f}%")
            else:
                click.echo("   ✅ No security threat detected")
                click.echo(f"   Confidence: {max(result['probability']) * 100:.2f}%")
            
    except Exception as e:
        click.echo(f"Error during prediction: {str(e)}", err=True)

@cli.command()
@click.option('--model-path', default='models/pretrained_model.pkl',
              help='Path to trained model')
def system(model_path):
    # Analyze system
    try:
        analyzer = SecurityAnalyzer(model_path)
        
        click.echo("🔍 Reading system data...")
        
        # Read system data
        system_data = analyzer.read_system_data()
        
        if not system_data:
            click.echo("No system data found.")
            return
        
        click.echo(f"Found {len(system_data)} system events to analyze...")
        
        # Analyze each event
        threat_count = 0
        for i, data in enumerate(system_data):
            result = analyzer.analyze_threat(data)
            
            if result['threat_status'] == 'THREAT':
                threat_count += 1
                click.echo(f"\n🚨 THREAT DETECTED:")
                click.echo(f"   Session ID: {data['session_id']}")
                click.echo(f"   Attack Type: {result['attack_type']}")
                click.echo(f"   Risk Score: {result['risk_score']}/100")
                click.echo(f"   Confidence: {result['confidence']}")
                
                if result['indicators']:
                    click.echo("   Indicators:")
                    for indicator in result['indicators']:
                        click.echo(f"      • {indicator}")
            else:
                click.echo(f"✅ Safe: {data['session_id']}")
        
        click.echo(f"\n📊 Summary: {threat_count} threats detected out of {len(system_data)} events")
        
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

@cli.command()
@click.option('--model-path', default='models/pretrained_model.pkl',
              help='Path to trained model')
def info(model_path):
    # Show model information
    try:
        if os.path.exists(model_path):
            click.echo("✅ Pre-trained model found")
            click.echo(f"📁 Model location: {model_path}")
            click.echo(" Ready for security threat detection!")
        else:
            click.echo("❌ Pre-trained model not found")
            click.echo("Please ensure the model file exists or contact support.")
    except Exception as e:
        click.echo(f"Error: {str(e)}", err=True)

@cli.command()
def demo():
    # Run a demo with sample data
    try:
        # Create sample data for demonstration
        sample_data = pd.DataFrame({
            'session_id': ['DEMO_001', 'DEMO_002', 'DEMO_003'],
            'network_packet_size': [800, 300, 1200],
            'protocol_type': ['UDP', 'TCP', 'ICMP'],
            'login_attempts': [8, 2, 6],
            'session_duration': [50, 500, 2500],
            'encryption_used': ['None', 'AES', 'DES'],
            'ip_reputation_score': [0.1, 0.8, 0.2],
            'failed_logins': [5, 0, 4],
            'browser_type': ['Chrome', 'Chrome', 'Firefox'],
            'unusual_time_access': [1, 0, 1]
        })
        
        # Save demo data
        demo_file = 'demo_data.csv'
        sample_data.to_csv(demo_file, index=False)
        
        click.echo("🎯 Running Security Threat Detection Demo...")
        click.echo("This will analyze 3 sample records with different threat levels.")
        
        # Run prediction on demo data
        analyzer = SecurityAnalyzer('models/pretrained_model.pkl')
        data = pd.read_csv(demo_file)
        
        for i, (_, row) in enumerate(data.iterrows()):
            # Analyze threat
            result = analyzer.analyze_threat(row)
            
            # Display results
            click.echo(f"\n📊 Analysis for Record {i+1}:")
            click.echo(f"   Session ID: {row['session_id']}")
            click.echo(f"   Attack Type: {result['attack_type']}")
            click.echo(f"   Confidence: {result['confidence']}")
            click.echo(f"   Risk Score: {result['risk_score']}/100")
            click.echo(f"   Timestamp: {result['timestamp']}")
            
            if result['indicators']:
                click.echo("   🚨 Threat Indicators:")
                for indicator in result['indicators']:
                    click.echo(f"      • {indicator}")
            
            # Show prediction result
            if result['threat_status'] == 'THREAT':
                click.echo("   🚨 SECURITY THREAT DETECTED!")
                click.echo(f"   Confidence: {max(result['probability']) * 100:.2f}%")
            else:
                click.echo("   ✅ No security threat detected")
                click.echo(f"   Confidence: {max(result['probability']) * 100:.2f}%")
        
        # Clean up
        os.remove(demo_file)
        
    except Exception as e:
        click.echo(f"Error during demo: {str(e)}", err=True)

if __name__ == '__main__':
    cli()
