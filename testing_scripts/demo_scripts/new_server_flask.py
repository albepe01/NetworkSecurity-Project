from flask import Flask, request, jsonify
import joblib
import sys
import os
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.models import PyModSecurity
from src.extractor import ModSecurityFeaturesExtractor
import toml
import numpy as np
import pandas as pd


# Inizializza il server Flask
app = Flask(__name__)


settings         = toml.load('config.toml')
crs_dir          = settings['crs_dir']
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

# Endpoint per la predizione combinata
@app.route("/predict", methods=["POST"])
def predict():
    data = request.json
    payload = data.get("payload", "")
    model_choice = data.get("model")
    dataset_choice = data.get("dataset")

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

if __name__ == "__main__":
    print("🚀 Avviando il server Flask con ModSecurity e modello ML...")
    app.run(port=6000)
