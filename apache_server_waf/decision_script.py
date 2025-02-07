#!/usr/bin/env python3.9

import sys
import os

os.environ['MPLCONFIGDIR'] = '/tmp/matplotlib'

# Aggiungi il percorso base del progetto al PYTHONPATH
sys.path.append("/home/cris/modsecproj/modsec-advlearn")

import json
import logging
from src.models import PyModSecurity
from src.extractor import ModSecurityFeaturesExtractor
import joblib
import numpy as np
import pandas as pd

# Configura il logger per scrivere nel file di audit
logging.basicConfig(filename='/var/log/modsec_combined_decisions.log', level=logging.INFO)

# Carica il modello
model_path = "/home/cris/modsecproj/modsec-advlearn/data/models_wafamole/adv_inf_svm_pl4_t1.joblib"
model = joblib.load(model_path)
# Features Extractor
extractor = ModSecurityFeaturesExtractor(crs_ids_path='/home/cris/modsecproj/modsec-advlearn/data/crs_sqli_ids_4.0.0.json', crs_path='/home/cris/modsecproj/modsec-advlearn/coreruleset/rules/', crs_pl=4)

# Esegui la decisione
def combined_decision(payload):
    # Predizione ModSecurity
    waf = PyModSecurity(rules_dir="/home/cris/modsecproj/modsec-advlearn/coreruleset/rules/", pl=1)
    waf_decision = "Blocked" if waf.predict(np.array([payload]))[0] > 0 else "Allowed"

    # ML Model Prediction
    features = extractor.extract_features(pd.DataFrame([{"payload": payload}]))
    prediction = model.predict([features[0]])[0]
    ml_decision = "Blocked" if prediction == 1 else "Allowed"

    # Decisione combinata (OR logico)
    combined_decision = "Blocked" if waf_decision == "Blocked" or ml_decision == "Blocked" else "Allowed"
    logging.info(f"Payload: {payload} | ModSec: {waf_decision} | ML: {ml_decision} | Combined: {combined_decision}")
    print(json.dumps({"waf_decision": waf_decision, "ml_decision": ml_decision, "combined_decision": combined_decision}))
    return combined_decision

if __name__ == "__main__":
    print("Enter in the decision script")
    print("Dati ricevuti dallo script:", sys.argv)
    # Legge il payload dal file temporaneo
    #with open("/tmp/modsec_payload.txt", "r") as f:
    #    payload = f.read().strip()
    #print("Payload: ", payload)
    #decision = combined_decision(payload)
    #if decision:
    #    print(decision)
    #    sys.exit(0)
    # Estrai il payload direttamente dagli argomenti
    if len(sys.argv) > 1:
        payload = sys.argv[1]
        print("Payload: ", payload)
        decision = combined_decision(payload)
        print(decision)
    else:
        print("❌ Nessun payload trovato negli argomenti.")
    sys.exit(0)
