
# Real-Time Network Intrusion Detection System

## Project Overview

A Python-based Network Intrusion Detection System
developed using Kali Linux and Scapy.

The system captures network packets, monitors TCP
connection attempts, detects possible port scanning
activity and generates security alerts.

## Technologies Used

- Kali Linux
- Python 3
- Scapy
- Streamlit
- SQLite
- Nmap
- Wireshark

## Features

- Network packet capture
- TCP SYN monitoring
- Possible port scan detection
- Source IP monitoring
- Security alert generation
- SQLite database storage
- Streamlit monitoring dashboard

## Installation

Clone the repository:

    git clone YOUR_GITHUB_REPOSITORY_URL

Enter the project directory:

    cd NIDS-Project

Create virtual environment:

    python3 -m venv .venv

Activate environment:

    source .venv/bin/activate

Install requirements:

    pip install -r requirements.txt

## Usage

Start IDS:

    sudo .venv/bin/python ids.py --interface lo

Start dashboard in another terminal:

    source .venv/bin/activate
    streamlit run dashboard.py

Open:

    http://localhost:8501

## Testing

Use Nmap against your own loopback interface:

    sudo nmap -sS -p 1-30 127.0.0.1

## Detection Method

The initial detection rule monitors TCP SYN
packets and counts unique destination ports
within a configurable time window.

## Limitations

- Rule-based detection only
- Possible false positives
- No encrypted payload inspection
- No automatic blocking
- Depends on available packet visibility

## Future Improvements

- UDP scan detection
- Brute-force login detection
- Email alerts
- Automatic dashboard refresh
- Advanced anomaly detection
- Machine learning-based detection

## Disclaimer

This project is intended for educational and
authorized security monitoring purposes only.
