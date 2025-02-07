import os
import sys
from flask import Flask, request, jsonify
sys.path.append(os.path.join(os.path.dirname(__file__), '..'))
from src.extractor import ModSecurityFeaturesExtractor
import joblib
import pandas as pd
import requests

# Percorsi dei modelli ML
model_paths = {
    "wafamole": {
        "rf": 'data/models_wafamole/adv_rf_pl4.joblib',
        "svm_linear_l1": 'data/models_wafamole/adv_linear_svc_pl4_l1.joblib',
        "svm_linear_l2": 'data/models_wafamole/adv_linear_svc_pl4_l2.joblib',
        "log_reg_l1": 'data/models_wafamole/adv_log_reg_pl4_l1.joblib',
        "log_reg_l2": 'data/models_wafamole/adv_log_reg_pl4_l2.joblib',
        "inf_svm": 'data/models_wafamole/adv_inf_svm_pl4_t1.joblib'
    },
    "modsec": {
        "rf": 'data/models/adv_rf_pl4.joblib',
        "svm_linear_l1": 'data/models/adv_linear_svc_pl4_l1.joblib',
        "svm_linear_l2": 'data/models/adv_linear_svc_pl4_l2.joblib',
        "log_reg_l1": 'data/models/adv_log_reg_pl4_l1.joblib',
        "log_reg_l2": 'data/models/adv_log_reg_pl4_l2.joblib',
        "inf_svm": 'data/models/adv_inf_svm_pl4_t1.joblib'
    }
}

# Inizializza il server Flask
app = Flask(__name__)

# Funzione per estrarre le caratteristiche dal payload
def extract_features(payload):
    extractor = ModSecurityFeaturesExtractor(crs_ids_path='./data/crs_sqli_ids_4.0.0.json', crs_path='./coreruleset/rules', crs_pl=4)
    features = extractor.extract_features(pd.DataFrame([{"payload": payload}]))
    return features[0]


# Funzione per il test con ModSecurity
def test_with_modsecurity(payload):
    result = requests.post("http://127.0.0.1/", data={"query": payload})
    print("Result ModSec:", result)
    return "Blocked" if result.status_code == 403 else "Allowed"


# Funzione per il test con il modello ML
def test_with_ml(payload, model_choice, dataset_choice):
    features = extract_features(payload)
    # Caricamento dei modelli all'avvio del server
    model = joblib.load(model_paths[dataset_choice][model_choice])
    print(f"Model: {dataset_choice}/{model_choice}/{model}")
    prediction = model.predict([features])[0]
    return "Blocked" if prediction == 1 else "Allowed"

# Endpoint principale per la predizione
@app.route("/vulnerable", methods=["POST"])
def vulnerable():
    payload = request.form.get("query", "")
    model_choice = request.form.get("model_choice", "")
    dataset_choice = request.form.get("dataset_choice", "")

    print(f"🔍 Ricevuto payload: {payload}")
    #print(f"🔍 Modello scelto: {model_choice} | Dataset: {dataset_choice}")

    try:
        # Test con ModSecurity
        modsec_result = test_with_modsecurity(payload)
        print(f"\n🔐 ModSecurity prediction: {modsec_result}")
        # Test con il modello ML
        ml_result = test_with_ml(payload, model_choice, dataset_choice)
        print(f"\n🔐 ML Model prediction: {ml_result}")

        # Decisione combinata: OR (Blocked se almeno uno dei due rileva il payload come malevolo)
        combined_decision = "Blocked" if modsec_result == "Blocked" or ml_result == "Blocked" else "Allowed"
        print(f"\n⚖️ Combined Decision: {combined_decision}")

        # Restituisce il risultato al client
        return jsonify({
            "modsec_prediction": modsec_result,
            "ml_prediction": ml_result,
            "combined_decision": combined_decision,
            "payload": payload
        })

    except Exception as e:
        print(f"❌ Errore interno del server: {str(e)}")
        return jsonify({"error": "Errore interno del server"}), 500


if __name__ == "__main__":
    print("🚀 Avviando il server Flask con decisione combinata...")
    app.run(port=6000)
