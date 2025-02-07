# Per avviare il programma client/server avviare prima il server apache con il comando ' sudo systemctl restart apache2'
# o simil, poi startare server_vulnerable.py su una finestra terminale, e quando il server è attivo lanciare questo client
# su un'altra finestra


import requests
import pandas as pd
import pickle
import json
import random
from my_utils import *

# URL del server Apache che passa per ModSecurity
url = "http://127.0.0.1:6000/vulnerable"

# List of available models
models =  ["rf", "svm_linear_l1", "svm_linear_l2", "log_reg_l1", "log_reg_l2", "inf_svm"]
# List of available payload types
payload_types = ["legitimate", "malicious", "adv_ms", "adv_ml"]
# List of available datasets
datasets = ["modsec", "wafamole"]



def load_payloads(dataset, idx):
    """Carica i payloads dal dataset specificato."""
    payload = dataset["payload"].iloc[idx % len(dataset)]
    return payload


def check_accuracy(combined_decision, payload_type):
    if payload_type == "legitimate":
        y_true = "Allowed"
    else:
        y_true = "Blocked"
    if combined_decision == y_true:
        print("\n🔝The classification is correct!!!🔝\n")
        


if __name__ == "__main__":

    print("🚀 Il Client è pronto per comunicare...")

    while(True):

        # Chiedi all'utente quale dataset utilizzare
        dataset_choice = input("Scegli il dataset (modsec/wafamole): ").strip().lower()
        if dataset_choice not in datasets:
            print("Dataset non valido. Riprova.")
            continue
            
        # Chiedi se usare payloads legittimi o malevoli
        payload_type = input("Scegli il tipo di payload (legitimate/malicious/adv_ms/adv_ml): ").strip().lower()
        if payload_type not in payload_types:
            print("❌ Scelta del tipo di payload non valida!")
            continue

        # Chiedi all'utente quale model utilizzare
        model_choice = input("Scegli il model (rf/svc_linear_l1/svm_linear_l2/log_reg_l1/log_reg_l2/inf_svm): ").strip().lower()
        if model_choice not in models:
            print("Modello non valido. Riprova.")
            continue

        # Construct the path to load the dataset
        payload_path = construct_path(dataset_choice, model_choice, payload_type)
        print(payload_path)

        # Carica il Dasaset selezionato    
        data = load_dataset(payload_path)

        idx = random.randint(0, len(data['payload'])-1)
        # Carica un payload with random idx dal dataset selezionato
        payload = load_payloads(data, idx)
        print(f"\n🔍 Upload the payload {idx} with lenght {len(payload)} from dataset {dataset_choice} ({payload_type})")

        # Send the payload
        combined_decision = send_requests(payload, model_choice, dataset_choice, url, verbose=True)

        check_accuracy(combined_decision, payload_type)

        user_input = input("Vuoi inviare una nuova richiesta? (y/n) ").strip().lower()
        if user_input != 'y':
            print("👋 END.")
            break
