import requests
import pandas as pd
import pickle
import json


models =  ["rf", "svm_linear_l1", "svm_linear_l2", "log_reg_l1", "log_reg_l2", "inf_svm"]

# Funzione per inviare i payload al server
def test_payload(payload, model_choice, dataset_choice):
    response = requests.post("http://127.0.0.1:6000/predict", json={"payload": payload, "model": model_choice, "dataset": dataset_choice})
    return response.json()

# Funzione per estrarre i payload dai dataset
def get_payloads(legit_path, mal_path, adv_path_ms, adv_path_ml, idx):
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

    # Carica i dataset
    legit_data = load_dataset(legit_path)
    mal_data = load_dataset(mal_path)
    adv_data_ms = load_dataset(adv_path_ms)
    adv_data_ml = load_dataset(adv_path_ml)

    # Seleziona il payload corretto utilizzando l'indice
    legit_payload = legit_data["payload"].iloc[idx % len(legit_data)]
    mal_payload = mal_data["payload"].iloc[idx % len(mal_data)]
    adv_payload_ms = adv_data_ms["payload"].iloc[idx % len(adv_data_ms)]
    adv_payload_ml = adv_data_ml["payload"].iloc[idx % len(adv_data_ml)]

    return legit_payload, mal_payload, adv_payload_ms, adv_payload_ml


# Main demo interattiva
if __name__ == "__main__":
    print("🚀 Avviando il test interattivo tra ModSecurity e il modello ML...")

    idx = 0
    while True:
        # Chiedi all'utente il dataset
        dataset_choice = input("Scegli il dataset (wafamole/modsec): ").strip().lower()
        if dataset_choice not in ["wafamole", "modsec"]:
            print("Dataset non valido. Riprova.")
            continue

        # Chiedi all'utente il modello
        model_choice = input("Scegli il modello di classificatore (rf/svc_linear_l1/svm_linear_l2/log_reg_l1/log_reg_l2/inf_svm): ").strip().lower()
        if model_choice not in models:
            print("Modello non valido. Riprova.")
            continue

        # Estrai i payload
        if dataset_choice == "wafamole":
            legit_path = "data/dataset_wafamole/legitimate_test.pkl"
            mal_path = "data/dataset_wafamole/malicious_test.pkl"
            adv_path_ms = "data/dataset_wafamole/adv_test_ms_pl1_rs20_100rounds.pkl"
            adv_path_ml = f"data/dataset_wafamole/adv_test_{model_choice}_pl4_rs20_100rounds.pkl"
        else:
            legit_path = "data/dataset/legitimate_test.json"
            mal_path = "data/dataset/malicious_test.json"
            adv_path_ms = "data/dataset/adv_test_ms_pl1_rs20_100rounds.json"
            adv_path_ml = f"data/dataset_wafamole/adv_test_{model_choice}_pl4_rs20_100rounds.pkl"

        legit_payload, mal_payload, adv_payload_ms, adv_payload_ml = get_payloads(legit_path, mal_path, adv_path_ms, adv_path_ml, idx)

        # Test con payload legittimo
        print("\n✅ [Payload Legittimo]")
        print(legit_payload)
        result = test_payload(legit_payload, model_choice, dataset_choice)
        if result["modsec_prediction"] == "Allowed":
            print("ModSecurity:", result["modsec_prediction"], "    ✅")
        else:
            print("ModSecurity:", result["modsec_prediction"], "    ❌")

        if result["ml_prediction"] == "Allowed":
            print("ML Model:", result["ml_prediction"], "    ✅")
        else:
            print("ML Model:", result["ml_prediction"], "    ❌")

        # Test con payload malevolo
        print("\n🚫 [Payload Malevolo]")
        print(mal_payload)
        result = test_payload(mal_payload, model_choice, dataset_choice)
        if result["modsec_prediction"] == "Allowed":
            print("ModSecurity:", result["modsec_prediction"], "    ❌")
        else:
            print("ModSecurity:", result["modsec_prediction"], "    ✅")

        if result["ml_prediction"] == "Allowed":
            print("ML Model:", result["ml_prediction"], "    ❌")
        else:
            print("ML Model:", result["ml_prediction"], "    ✅")
               

        # Test con payload adversarial
        print("\n⚠️ [Payload Adversarial]")
        print("ModSecurity: ", adv_payload_ms)
        print("ML Model: ", adv_payload_ml)
        result_ms = test_payload(adv_payload_ms, model_choice, dataset_choice)
        result_ml = test_payload(adv_payload_ml, model_choice, dataset_choice)
        if result_ms["modsec_prediction"] == "Allowed":
            print("ModSecurity:", result_ms["modsec_prediction"], "    ❌")
        else:
            print("ModSecurity:", result_ms["modsec_prediction"], "    ✅")

        if result_ml["ml_prediction"] == "Allowed":
            print("ML Model:", result_ml["ml_prediction"], "    ❌")
        else:
            print("ML Model:", result_ml["ml_prediction"], "    ✅")

        # Chiedi all'utente se continuare
        user_input = input("\nVuoi eseguire un altro test? (y/n): ").strip().lower()
        if user_input != 'y':
            print("👋 Demo terminata.")
            break

        idx += 1
