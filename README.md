# 🛡️ WebShield Scanner

A comprehensive Website Vulnerability Scanner built using Python that helps identify common security weaknesses in web applications and servers.

## 📌 Overview

WebShield Scanner is a cybersecurity assessment tool designed to perform automated security checks against websites and web servers. It combines network scanning, security header analysis, SSL certificate validation, and vulnerability detection into a single platform.

The project is intended for educational purposes and authorized security assessments only.

---

## 🚀 Features

### 🔍 Port Scanning

* Multi-threaded TCP port scanning
* Common service detection
* Open and closed port identification
* Scan duration tracking

### 🛡️ Security Header Analysis

Checks for:

* Content-Security-Policy (CSP)
* Strict-Transport-Security (HSTS)
* X-Frame-Options
* X-Content-Type-Options
* Referrer-Policy
* Permissions-Policy

### 🔐 SSL/TLS Certificate Inspection

* Certificate validation
* Expiration monitoring
* Issuer information
* TLS version checks
* Weak SSL configuration detection

### ⚠️ Vulnerability Detection

* SQL Injection indicators
* Cross-Site Scripting (XSS) indicators
* Directory listing exposure
* Sensitive information disclosure
* Exposed admin panels
* Robots.txt analysis

### 📊 Security Risk Scoring

* Vulnerability severity classification
* Overall security score generation
* Risk-based recommendations

### 📄 PDF Report Generation

Professional reports including:

* Executive Summary
* Security Findings
* Risk Assessment
* Recommendations
* Port Scan Results
* SSL Analysis
* Vulnerability Details

### 📈 Dashboard

* Security score visualization
* Severity charts
* Historical scan tracking
* Vulnerability statistics

---

## 🏗️ Project Architecture

```text
User
 │
 ▼
Frontend Dashboard
 │
 ▼
REST API (Flask/FastAPI)
 │
 ├── Port Scanner
 ├── Header Analyzer
 ├── SSL Checker
 ├── Vulnerability Detector
 ├── Risk Engine
 └── Report Generator
 │
 ▼
SQLite Database
 │
 ▼
PDF Reports
```

---

## 🛠️ Technology Stack

### Backend

* Python 3.x
* Flask / FastAPI
* Socket Programming
* Requests
* BeautifulSoup
* SSL Module
* ReportLab

### Frontend

* HTML5
* CSS3
* JavaScript
* Bootstrap 5
* Chart.js

### Database

* SQLite

### Deployment

* Docker
* Linux Compatible

---

## 📂 Project Structure

```text
webshield-scanner/
│
├── backend/
├── frontend/
├── scanner/
├── header_checker/
├── ssl_checker/
├── vulnerability_detector/
├── pdf_generator/
├── reports/
├── database/
├── static/
├── templates/
├── tests/
├── docs/
├── Dockerfile
├── requirements.txt
└── README.md
```

---

## ⚙️ Installation

### Clone Repository

```bash
git clone https://github.com/yourusername/webshield-scanner.git

cd webshield-scanner
```

### Create Virtual Environment

```bash
python -m venv venv
```

### Activate Environment

Windows:

```bash
venv\Scripts\activate
```

Linux/Mac:

```bash
source venv/bin/activate
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Application

```bash
python app.py
```

or

```bash
uvicorn main:app --reload
```

---

## 📡 API Endpoints

### Start Scan

```http
POST /scan
```

Request:

```json
{
  "url": "https://example.com"
}
```

### Get Report

```http
GET /report/{scan_id}
```

### Get Scan History

```http
GET /history
```

### Dashboard Statistics

```http
GET /dashboard
```

---

## 📄 Sample Report Contents

* Target URL
* Scan Timestamp
* Open Ports
* Security Headers
* SSL Certificate Details
* Vulnerability Findings
* Risk Score
* Recommendations

---

## 🔒 Security Notice

This project is intended only for:

✅ Educational purposes

✅ Authorized security assessments

✅ Personal laboratory environments

Do not scan websites, servers, or networks without explicit permission.

The developer assumes no responsibility for misuse.

---

## 🎯 Learning Outcomes

This project demonstrates:

* Network Programming
* Socket Programming
* Cybersecurity Fundamentals
* Web Security Concepts
* Vulnerability Assessment
* REST API Development
* Database Management
* Report Generation
* Full Stack Development
* Docker Deployment

---

## 💼 Resume Description

Developed a Python-based Website Vulnerability Scanner capable of performing port scanning, HTTP security header analysis, SSL certificate validation, and passive vulnerability detection. Implemented automated PDF reporting, risk scoring, REST APIs, and dashboard visualization using Flask/FastAPI, SQLite, and Chart.js.

---

## 🎤 Interview Questions

### Why did you build this project?

To gain practical experience in cybersecurity assessment, networking, and secure software development while understanding how vulnerability scanners work internally.

### What cybersecurity concepts are used?

* Vulnerability Assessment
* Risk Analysis
* SSL/TLS Security
* Security Headers
* Web Application Security
* Port Scanning

### What networking concepts are used?

* TCP/IP
* Sockets
* Ports
* DNS
* HTTP/HTTPS Protocols

### What Python concepts are used?

* Multithreading
* OOP
* API Development
* File Handling
* Database Integration
* PDF Generation

---

## 📜 License

MIT License

---

## 👨‍💻 Author

Sachchidanand jha
B.Tech Computer Science & Engineering (2025)

Cybersecurity | Networking | Python Development
