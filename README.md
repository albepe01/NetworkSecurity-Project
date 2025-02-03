# **NetworkSecurity Project**  
## **WAF Combining ModSecurity and Machine Learning for SQL Injection Protection**

This project demonstrates a practical approach to enhancing Web Application Firewall (WAF) defenses by integrating traditional signature-based protection, provided by **ModSecurity**, with modern machine learning-based anomaly detection from the **ModSec-AdvLearn** framework. The goal is to achieve a **combined decision-making system** to detect and block **SQL Injection (SQLi)** attacks more effectively in a **simulated real-world environment using Apache**.

By combining these two complementary approaches, we can mitigate both known and unknown (zero-day) SQL injection threats through continuous learning and rule-based protection.

---

## **Table of Contents**
1. [Project Overview](#project-overview)  
2. [Key Features](#key-features)  
3. [Architecture](#architecture)  
4. [Installation&Usage](#installation)  
5. [Directory Structure](#directory-structure)  

---

## **Project Overview**  
The primary challenge of traditional WAFs like ModSecurity is their reliance on static rule sets that are unable to adapt to unknown or evolving attack patterns. This project extends the WAF capabilities by integrating a machine learning model trained on adversarial samples and standard SQL injection payloads. **The machine learning model detects anomalies** beyond the scope of static rules, making it ideal for catching sophisticated and obfuscated attacks.

---

## **Key Features**
- **Hybrid Decision System:** Combines ModSecurity’s rule-based approach with real-time predictions from a trained machine learning model.  
- **Adversarial Training Protection:** Uses **WAF-A-MoLE**-generated adversarial samples to train the machine learning model, providing better resilience to bypass attempts.  
- **Apache Integration:** Fully integrated with the Apache web server to simulate realistic traffic and enforce blocking decisions.  
- **Customizable Models:** Easily switch between different classifiers (Random Forest, SVM, Logistic Regression) to compare performance.  
- **Extensive Evaluation:** Performance metrics such as accuracy, ROC curves, and F1 scores are evaluated for combined and individual decisions.  

---

## **Architecture**
```plaintext
      +----------------------------------+
      | Client (malicious or legitimate) |
      +-----------------+----------------+
                        |
                        v
    +-----------------------------------------+
    | Flask Server with Combined Decision Logic|
    +-----------------------------------------+
                          |
           ----------------------------------
           |                                |
           v                                v
+--------------------+        +-----------------------------+
|   ML Predictions   |        | Apache with ModSecurity WAF |
+--------------------+        +-----------------------------+
           |                                |
           +--------------------------------+
                          |
                          v
            Combined Decision (Allow or Block)
```
---

## **Installation**

### Step 1: Install Environment and Python dependencies
As first step, follow the guidelines provided by [ModSec-AdvLearn](https://github.com/pralab/modsec-advlearn/tree/main) considering that we are working with Ubuntu 18.04, so it's necessary to install manually a version of python 3.9.

### Step 2: Install Python dependencies
Once the environment is configured, it's easy to add our new implemented scripts and use the models pre-trained with ModSec-AdvLearn framework. 
Make sure to install Flask and other key libraries included in the requirements.txt file of ModSec-AdvLearn.

### Step 3: Install and configure ModSecurity with Apache
Follow these steps to install and enable ModSecurity:
```bash
sudo apt update
sudo apt install apache2 libapache2-mod-security2
```
Enable ModSecurity and restart Apache:
```bash
sudo a2enmod security2
sudo systemctl restart apache2
```
Verify that ModSecurity is enabled:
```bash
sudo apachectl -M | grep security
```
If you see security2_module in the output, ModSecurity is correctly enabled.

### Step 4: Configure ModSecurity and CRS rules
Edit the ModSecurity configuration file:
```bash
sudo nano /etc/modsecurity/modsecurity.conf
```
Set the engine to On:
```plaintext
SecRuleEngine On
```
Enable the Core Rule Set (CRS):
```bash
sudo apt install modsecurity-crs
```

Restart Apache:
```bash
sudo systemctl restart apache2
```

### Step 5: Set up the Flask server
Run the Flask server, which handles requests and makes machine learning predictions:
```bash
python3 scripts/server_flask.py
```
You should see a message indicating the server is running at http://127.0.0.1:6000.

Usage
To test the system and evaluate its performance you can now launch the client side and send queries.
The client will then automatically send payloads to the server via ModSecurity and display the combined decision.

## **Directory Structure**
```bash
NetworkSecurity-Project/
│
├── ModSecurity/
│  
├── modsec-advlearn/
│   ├── data/                      
│   │   ├── dataset/              # Normal and adversarial datasets (modsec)
│   │   ├── data_wafamole/        # Normal and adversarial datasets (wafamole)
│   │   ├── models/               # Trained models on modsec dataset 
│   │   └── models_wafamole/      # Trained models on wafamole dataset 
│   ├── src/
│   ├── scripts/                   # Scripts of the repository ModSec-AdvLearn
│   ├── new_scripts/               # Our Added Scripts
│   │   ├── client.py
│   │   ├── ...                  
│   │   └── server_flask.py              
│   └── new_results/               # Our Results
│
├── pymodsecurity/
│
└── WAF-A-MoLE/                  
```









