"""
Funzionamento generale:
Client (complete_client_eval.py):

Il client invia un payload al server Flask tramite una richiesta POST all'endpoint http://127.0.0.1:6000/vulnerable.
In ogni richiesta, il client invia anche il model_choice e il dataset_choice, che sono fondamentali per il server.
Server Flask (server_vulnerable.py):

Il server riceve la richiesta dal client contenente il payload e le informazioni sui modelli.
Testa il payload in due modi:
ModSecurity WAF: Inoltra il payload a http://127.0.0.1/vulnerable (gestito da Apache), verificando se ModSecurity blocca il payload o no.
Modello ML: Utilizza il modello scelto per classificare il payload come "Blocked" o "Allowed".
Decisione combinata:

Il server combina i risultati di ModSecurity e del modello ML. Se uno dei due rileva il payload come malevolo (Blocked), la decisione combinata è "Blocked" (OR logico).
Dettagli chiave:
Apache VirtualHost/Endpoint Apache:
L’endpoint http://127.0.0.1/vulnerable di Apache gestisce il traffico verso ModSecurity. Non è un endpoint creato manualmente, ma fa parte della configurazione di Apache con il WAF attivo.

Quando il payload viene inviato ad Apache:
Se il payload viola le regole del WAF (ad esempio, una regola SQLi), ModSecurity risponde con uno stato HTTP 403 Forbidden.
Altrimenti, Apache restituisce 200 OK o 404 Not Found se l’endpoint non esiste.
Differenza tra il server Flask e Apache:

Apache è responsabile di fornire la decisione del WAF.
Flask è il livello intermedio che riceve la richiesta dal client, interroga Apache per la decisione del WAF, e allo stesso tempo interroga il modello ML per ottenere la predizione.
"""

import requests
import pandas as pd
import pickle
import json
from sklearn.metrics import accuracy_score, roc_auc_score, f1_score, classification_report
import numpy as np
from my_utils import *
import matplotlib.pyplot as plt
import os
from sklearn.metrics import accuracy_score, roc_auc_score, f1_score, classification_report, roc_curve
from sklearn.utils import shuffle


# URL del server Apache che passa per ModSecurity
url = "http://127.0.0.1:6000/vulnerable"

# List of available models
models = ["rf", "svm_linear_l1", "svm_linear_l2", "log_reg_l1", "log_reg_l2", "inf_svm"]
# List of available payload types
payload_types = ["legitimate", "malicious", "adv_ms", "adv_ml"]
# List of available datasets
datasets = ["wafamole", "modsec"]


def plot_and_save_roc_curve(y_true, y_pred, output_dir):
    """Genera e salva la curva ROC."""
    fpr, tpr, _ = roc_curve(y_true, y_pred)
    plt.figure()
    plt.plot(fpr, tpr, color='blue', lw=2, label='ROC Curve (AUC = {:.4f})'.format(roc_auc_score(y_true, y_pred)))
    plt.plot([0, 1], [0, 1], color='gray', lw=1, linestyle='--')
    plt.xlabel('False Positive Rate')
    plt.ylabel('True Positive Rate')
    plt.title('ROC Curve')
    plt.legend(loc='lower right')
    plt.grid(True)
    plt.savefig(os.path.join(output_dir, "roc_curve.png"))
    plt.close()

def save_performance_report(y_true, y_pred, output_dir):
    """Salva il rapporto di classificazione e le metriche in un file di testo."""
    accuracy = accuracy_score(y_true, y_pred)
    f1 = f1_score(y_true, y_pred)
    roc_auc = roc_auc_score(y_true, y_pred)
    report = classification_report(y_true, y_pred, target_names=["Allowed", "Blocked"])
    with open(os.path.join(output_dir, "performance_report.txt"), "w") as f:
        f.write("📊 Risultati delle prestazioni:\n")
        f.write(f"🔹 Accuratezza: {accuracy:.4f}\n")
        f.write(f"🔹 F1-Score: {f1:.4f}\n")
        f.write(f"🔹 AUC-ROC: {roc_auc:.4f}\n\n")
        f.write("📄 Rapporto di classificazione:\n")
        f.write(report)
    # Salva i vettori per eventuali analisi future
    np.save(os.path.join(output_dir, "y_true.npy"), y_true)
    np.save(os.path.join(output_dir, "y_pred.npy"), y_pred)


def combine_datasets(legitimate_data, malicious_data, adv_ms_data=None, adv_ml_data=None):
    """Combina i payloads legittimi, malevoli e opzionali avversari in un unico dataset."""
    combined_payloads = []
    true_labels = []

    # Aggiungi i payloads legittimi (label 0)
    combined_payloads.extend(legitimate_data['payload'].tolist())
    true_labels.extend([0] * len(legitimate_data))

    # Aggiungi i payloads malevoli (label 1)
    combined_payloads.extend(malicious_data['payload'].tolist())
    true_labels.extend([1] * len(malicious_data))

    # Aggiungi i payloads avversari (label 1)
    if adv_ms_data is not None:
        combined_payloads.extend(adv_ms_data['payload'].tolist())
        true_labels.extend([1] * len(adv_ms_data))

    # Aggiungi i payloads avversari (label 1)
    if adv_ml_data is not None:
        combined_payloads.extend(adv_ml_data['payload'].tolist())
        true_labels.extend([1] * len(adv_ml_data))

    # Shuffle del dataset
    combined_payloads, true_labels = shuffle(np.array(combined_payloads), np.array(true_labels), random_state=42)
    return combined_payloads, true_labels



def main():
    print("🚀 Il Client è pronto per inviare tutti i payload del dataset...")

    # Chiedi all'utente quale dataset utilizzare
    #dataset_choice = input("Scegli il dataset (modsec/wafamole): ").strip().lower()
    #if dataset_choice not in datasets:
    #    print("❌ Dataset non valido. Uscita.")
    #    return
    for dataset_choice in datasets:
        print("Dataset: ", dataset_choice)

        # Chiedi se includere i payload avversari
        #include_adversarial = input("Vuoi includere anche i payload avversari? (y/n): ").strip().lower() == 'y'
        include_adversarial = False

        # Chiedi all'utente quale modello utilizzare
        #model_choice = input("Scegli il modello (rf/svc_linear_l1/svm_linear_l2/log_reg_l1/log_reg_l2/inf_svm): ").strip().lower()
        #if model_choice not in models:
        #    print("❌ Modello non valido. Uscita.")
        #    return

        for model_choice in models:
            print("Model", model_choice)

            if include_adversarial:
                # Directory di output per salvare i risultati
                output_dir = f"results/{dataset_choice}_with_adv/{model_choice}"
                os.makedirs(output_dir, exist_ok=True)
            else:
                # Directory di output per salvare i risultati
                output_dir = f"results/{dataset_choice}/{model_choice}"
                os.makedirs(output_dir, exist_ok=True)

            # Percorso del file di output
            output_file = os.path.join(output_dir, "performance_report.txt")
            # Se il file esiste già, salta l'iterazione corrente
            if os.path.isfile(output_file):
                print(f"⚠️ The output file {output_file} already exists. Skipping to next model...")
                continue

            # Costruisci i percorsi dei dataset
            legitimate_path = construct_path(dataset_choice, model_choice, payload_type="legitimate")
            malicious_path = construct_path(dataset_choice, model_choice, payload_type="malicious")
            if include_adversarial:
                adv_ms_path = construct_path(dataset_choice, model_choice, payload_type="adv_ms")
                adv_ml_path = construct_path(dataset_choice, model_choice, payload_type="adv_ml")

            # Carica i dataset
            legitimate_data = load_dataset(legitimate_path)
            malicious_data = load_dataset(malicious_path)
            if include_adversarial:
                adv_ms_data = load_dataset(adv_ms_path) if adv_ms_path else None
                adv_ml_data = load_dataset(adv_ml_path) if adv_ml_path else None
                # Combina i dataset
                combined_payloads, y_true = combine_datasets(legitimate_data, malicious_data, adv_ms_data, adv_ml_data)
            else:
                # Combina i dataset
                combined_payloads, y_true = combine_datasets(legitimate_data, malicious_data)

            # Inizializza i risultati
            y_pred = []

            # Invia ogni payload
            for idx, payload in enumerate(combined_payloads):
                print(f"\n🔍 [Send payload {idx + 1} of {len(combined_payloads)} ({dataset_choice}, {model_choice})]")
                decision = send_requests(payload, model_choice, dataset_choice, url, verbose=True)
                # Aggiorna i risultati
                y_pred.append(1 if decision == "Blocked" else 0)

            # Calcola e mostra le metriche
            print("\n📊 Risultati delle prestazioni:")
            accuracy = accuracy_score(y_true, y_pred)
            f1 = f1_score(y_true, y_pred)
            roc_auc = roc_auc_score(y_true, y_pred)
            print(f"🔹 Accuratezza: {accuracy:.4f}")
            print(f"🔹 F1-Score: {f1:.4f}")
            print(f"🔹 AUC-ROC: {roc_auc:.4f}")

            # Salva il rapporto di classificazione e le metriche
            save_performance_report(y_true, y_pred, output_dir)
            # Genera e salva la curva ROC
            plot_and_save_roc_curve(y_true, y_pred, output_dir)


if __name__ == "__main__":
    main()
