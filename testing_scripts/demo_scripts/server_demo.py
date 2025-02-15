from flask import Flask, request, jsonify, render_template
import joblib
import sys
import os
import requests
import pandas as pd
import pickle
import json
import numpy as np
import toml

sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.models import PyModSecurity
from src.extractor import ModSecurityFeaturesExtractor

# Inizializza il server Flask
app = Flask(__name__)

settings = toml.load('config.toml')
crs_dir = settings['crs_dir']
print(crs_dir)

# Inizializza ModSecurity
modsec = PyModSecurity(rules_dir="./coreruleset/rules/", pl=1)

# Percorsi dei modelli ML
model_paths = {
    "wafamole": {
        "rf": 'data/models_wafamole/adv_rf_pl4.joblib',
        "svc_linear_l1": 'data/models_wafamole/adv_linear_svc_pl4_l1.joblib',
        "svc_linear_l2": 'data/models_wafamole/adv_linear_svc_pl4_l2.joblib',
        "log_reg_l1": 'data/models_wafamole/adv_log_reg_pl4_l1.joblib',
        "log_reg_l2": 'data/models_wafamole/adv_log_reg_pl4_l2.joblib',
        "inf_svm": 'data/models_wafamole/adv_inf_svm_pl4_t1.joblib'
    },
    "modsec": {
        "rf": 'data/models/adv_rf_pl4.joblib',
        "svc_linear_l1": 'data/models/adv_linear_svc_pl4_l1.joblib',
        "svc_linear_l2": 'data/models/adv_linear_svc_pl4_l2.joblib',
        "log_reg_l1": 'data/models/adv_log_reg_pl4_l1.joblib',
        "log_reg_l2": 'data/models/adv_log_reg_pl4_l2.joblib',
        "inf_svm": 'data/models/adv_inf_svm_pl4_t1.joblib'
    }
}

# Estrattore di caratteristiche
extractor = ModSecurityFeaturesExtractor(crs_ids_path='./data/crs_sqli_ids_4.0.0.json', crs_path='./coreruleset/rules/', crs_pl=4)

models = ["rf", "svm_linear_l1", "svm_linear_l2", "log_reg_l1", "log_reg_l2", "inf_svm"]

# Funzione per caricare il file in base all'estensione
def load_dataset(file_path):
    if file_path.endswith(".pkl"):
        with open(file_path, "rb") as f:
            data = pd.DataFrame(pickle.load(f), columns=["payload"])
    elif file_path.endswith(".json"):
        with open(file_path, "r") as f:
            data = pd.DataFrame(json.load(f), columns=["payload"])
    else:
        raise ValueError(f"Formato non supportato per il file: {file_path}")
    return data

# Funzione per estrarre i payload dai dataset
def get_payload_from_index(dataset_choice, model_choice, payload_type, idx):
    if dataset_choice == 'wafamole':       
        legit_path = "data/dataset_wafamole/legitimate_test.pkl"
        mal_path = "data/dataset_wafamole/malicious_test.pkl"
        adv_path_ms = "data/dataset_wafamole/adv_test_ms_pl1_rs20_100rounds.pkl"
        adv_path_ml = f"data/dataset_wafamole/adv_test_{model_choice}_pl4_rs20_100rounds.pkl"
    else:
        legit_path = "data/dataset/legitimate_test.json"
        mal_path = "data/dataset/malicious_test.json"
        adv_path_ms = "data/dataset/adv_test_ms_pl1_rs20_100rounds.json"
        adv_path_ml = f"data/dataset/adv_test_{model_choice}_pl4_rs20_100rounds.json"

    # Carica i dataset
    if payload_type == "legit":
        data = load_dataset(legit_path)
    elif payload_type == "malicious":
        data = load_dataset(mal_path)
    elif payload_type == "adversarial_modsec":
        data = load_dataset(adv_path_ms)
    elif payload_type == "adversarial_ml":
        data = load_dataset(adv_path_ml)
    else:
        raise ValueError(f"Tipo di payload non supportato: {payload_type}")

    # Seleziona il payload corretto utilizzando l'indice
    payload = data["payload"].iloc[idx % len(data)]
    print("Payload: ",payload)

    return payload

# Endpoint per la predizione combinata
@app.route("/predict", methods=["POST"])
def predict():
    data = request.json
    payload = data.get("payload", "")
    model_choice = data.get("model")
    dataset_choice = data.get("dataset")
    payload_type = data.get("payloadType")
    payload_index = data.get("payloadIndex")

    # Se il payload non è specificato, utilizza l'indice per selezionare un payload dal dataset
    if not payload and payload_index is not None:
        payload = get_payload_from_index(dataset_choice, model_choice, payload_type, int(payload_index))

    # Controlla se il modello richiesto esiste
    if model_choice not in model_paths[dataset_choice]:
        return jsonify({"error": f"Modello '{model_choice}' non valido per il dataset '{dataset_choice}'."}), 400

    # Carica il modello
    model = joblib.load(model_paths[dataset_choice][model_choice])

    # Predizione ModSecurity
    modsec_result = "Blocked" if modsec.predict(np.array([payload]))[0] > 0 else "Allowed"

    # Predizione modello ML
    features = extractor.extract_features(pd.DataFrame([{"payload": payload}]))
    prediction = model.predict([features[0]])[0]
    ml_result = "Blocked" if prediction == 1 else "Allowed"

    # Restituisci entrambe le predizioni
    return jsonify({
        "modsec_prediction": modsec_result,
        "ml_prediction": ml_result,
        "payload": payload,
        "model_used": model_choice,
        "dataset_used": dataset_choice
    })

# Endpoint per la pagina principale
@app.route("/")
def index():
    return render_template("index.html")

if __name__ == "__main__":
    print("🚀 Avviando il server Flask con ModSecurity e modello ML...")
    app.run(port=5000)