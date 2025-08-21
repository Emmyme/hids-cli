# HIDS CLI - Security Threat Detection Tool

A Python CLI tool for detecting security threats using machine learning. It combines rule-based detection with a pre-trained Random Forest model.

## Features

- **Pre-trained ML Model**: 89.36% accuracy
- **System Monitoring**: Analyze network connections (limited to available system data)
- **Multiple Attack Detection**: Brute Force, DDoS, Credential Stuffing, Session Hijacking, Data Exfiltration
- **Risk Scoring**: 0-100 scale assessment

## Quick Start

### Install

```bash
git clone <your-repo-url>
cd hids-cli
pip install -r requirements.txt
```

### Run Demo

```bash
python -m src.main demo
```

### Analyze Your System

```bash
python -m src.main system
```

**System Monitoring Scope:**

- **Network connections**: Current active connections only (real-time snapshot)
- **Security events**: Last 10 login events from Windows Security log
- **Data limitations**: Most fields use estimated/defaults (Windows doesn't provide rich training data)
- **Time range**: Current moment only, no historical analysis

_Note: The ML model was trained on comprehensive cybersecurity datasets with detailed features like packet sizes, session durations, IP reputation scores, and encryption details. Windows system monitoring provides limited data, so this is primarily a demonstration. For full effectiveness, the model needs the rich data it was trained on._

### Check Status

```bash
python -m src.main info
```

## Commands

| Command                       | Description                 |
| ----------------------------- | --------------------------- |
| `demo`                        | Run analysis on sample data |
| `system`                      | Analyze current system      |
| `predict --input-file <file>` | Analyze custom CSV          |
| `info`                        | Check model status          |

## CSV Format

Your CSV should have these columns:

- `session_id`, `network_packet_size`, `protocol_type`
- `login_attempts`, `session_duration`, `encryption_used`
- `ip_reputation_score`, `failed_logins`, `browser_type`
- `unusual_time_access`

## Example Output

```
📊 Analysis for Record 1:
   Attack Type: Brute Force
   Risk Score: 44/100
   🚨 SECURITY THREAT DETECTED!
   Confidence: 100.00%
```

## Development

Retrain the model:

```bash
python scripts/train_model.py
```

## License

MIT License - see [LICENSE](LICENSE) file.

## Dataset

Uses [Cybersecurity Intrusion Detection Dataset](https://www.kaggle.com/datasets/dnkumars/cybersecurity-intrusion-detection-dataset) by dnkumars (MIT License).
