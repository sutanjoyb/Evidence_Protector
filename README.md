# Evidence Protector

## Project Overview
Evidence Protector is a log analysis tool that helps verify the integrity of digital evidence. It analyzes system log files to detect unusual time gaps that may indicate potential tampering or system inconsistencies.

## Purpose
This project aims to identify irregularities in log data by:
- Extracting timestamps from log entries  
- Calculating time differences between consecutive events  
- Detecting abnormal gaps that may indicate possible tampering or system issues  

## Installation / Setup

### 1. Clone the repository
git clone https://github.com/sutanjoyb/Evidence_Protector.git  
cd Evidence_Protector  

### 2. Create a virtual environment
python -m venv venv  

Activate the environment:

Windows:  
venv\Scripts\activate  

macOS / Linux:  
source venv/bin/activate  

### 3. Install dependencies
pip install -r requirements.txt  

## Usage Instructions

### Run the application
python main.py  

### Access the application
Open your browser and go to:  
http://127.0.0.1:8000  

From there, you can:
- Login  
- Upload a log file  
- Analyze the results  

## Dependencies Required
- Python 3.9+  
- FastAPI  
- Uvicorn  
- python-jose  
- passlib  
- python-dotenv  

## Contribution Guidelines
To contribute to this project:

1. Fork the repository  
2. Create a new branch  
git checkout -b feature/your-feature-name  

3. Make your changes  
4. Commit your changes  
git commit -m "Describe your changes"  

5. Push to your fork  
git push origin feature/your-feature-name  

6. Open a Pull Request  