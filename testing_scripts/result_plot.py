import os
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends.backend_pdf import PdfPages
from sklearn.metrics import roc_curve, auc, precision_score, recall_score, f1_score, accuracy_score
import pandas as pd

# Directory structure (modify if needed)
results_dir = "./results"
output_dir = "./new_results/roc_combined_decision"
os.makedirs(output_dir, exist_ok=True)

# Dataframe to store the performance summary
summary_data = []
roc_data = {}  # Store ROC data to plot multiple models together
pdf_path = os.path.join(output_dir, "combined_roc_curves.pdf")

# Initialize PDF file
with PdfPages(pdf_path) as pdf:
    # Walk through the directory
    for dataset in os.listdir(results_dir):
        dataset_path = os.path.join(results_dir, dataset)
        if os.path.isdir(dataset_path):
            roc_data[dataset] = {}  # Initialize dataset key
            for model in os.listdir(dataset_path):
                model_path = os.path.join(dataset_path, model)
                if os.path.isdir(model_path):
                    # Load y_true and y_pred
                    y_true = np.load(os.path.join(model_path, "y_true.npy"))
                    y_pred = np.load(os.path.join(model_path, "y_pred.npy"))

                    # Calculate ROC curve and AUC
                    fpr, tpr, _ = roc_curve(y_true, y_pred)
                    roc_auc = auc(fpr, tpr)

                    # Store ROC data for later combined plot
                    roc_data[dataset][model] = (fpr, tpr, roc_auc)

                    # Calculate performance metrics directly
                    y_pred_binary = (y_pred > 0.5).astype(int)
                    accuracy = accuracy_score(y_true, y_pred_binary)
                    f1 = f1_score(y_true, y_pred_binary, average='weighted')
                    precision_blocked = precision_score(y_true, y_pred_binary, pos_label=1, zero_division=0)
                    recall_blocked = recall_score(y_true, y_pred_binary, pos_label=1, zero_division=0)

                    # Append to summary table
                    summary_data.append({
                        "Dataset": dataset,
                        "Model": model,
                        "AUC": roc_auc,
                        "Accuracy": accuracy,
                        "F1-Score": f1,
                        "Precision (Blocked)": precision_blocked,
                        "Recall (Blocked)": recall_blocked
                    })

    # Create a figure and subplots
    fig, axes = plt.subplots(nrows=(len(roc_data) + 1) // 2, ncols=2, figsize=(14, 6 * ((len(roc_data) + 1) // 2)), squeeze=False)  # Adjust subplot grid dynamically

    handles_labels = {}  # Use dictionary to collect unique handles and labels for shared legend
    labels = []  # To collect unique labels for the shared legend

    # Iterate through datasets and models
    for i, (dataset, models) in enumerate(roc_data.items()):
        ax = axes[i // 2, i % 2]  # Correctly position the subplot
        for model, (fpr, tpr, roc_auc) in models.items():
            line, = ax.plot(fpr, tpr, lw=2, label=f'{model} (AUC = {roc_auc:.2f})')
            if model not in handles_labels:
                handles_labels[model] = line
            if model not in labels:
                labels.append(f'{model}')
        ax.plot([0, 1], [0, 1], color='gray', linestyle='--')  # Diagonal line
        #ax.set_xscale('log')  # Log scale for FPR
        ax.set_xlabel('False Positive Rate (Log Scale)')
        ax.set_ylabel('True Positive Rate')
        ax.set_xlim([0.2, 1.0])
        ax.set_ylim([0.9, 1.0])  # Zoom on the y-axis between 0.8 and 1
        ax.set_title(f'{dataset}', fontsize=14)
        ax.grid(True)

    # Adjust layout and add shared legend below the plots
    fig.legend(handles_labels.values(), handles_labels.keys(), loc='lower center', bbox_to_anchor=(0.5, -0.05), ncol=4, fontsize='large', frameon=False)
    plt.tight_layout(rect=[0, 0.1, 1, 1])  # Leave space for the legend

    # Save the combined figure to the PDF
    pdf.savefig(fig)
    plt.close(fig)

# Create a summary table and save it
summary_df = pd.DataFrame(summary_data)
summary_table_path = os.path.join(output_dir, "performance_summary.csv")
summary_df.to_csv(summary_table_path, index=False)

print(f"Summary table saved to: {summary_table_path}")
print(f"Combined ROC curves saved to: {pdf_path}")
