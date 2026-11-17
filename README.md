\# AIDAS — AI-Powered Cyberattack Detection and Unknown Attack Identification System



AIDAS is an academic cybersecurity project that combines machine learning, experimental anomaly detection, passive network monitoring, and an interactive Flask dashboard.



\## Features



\- Binary and multiclass network attack classification

\- Logistic Regression, Decision Tree, and Random Forest models

\- Isolation Forest anomaly detection

\- Controlled withheld-attack-category experiments

\- Passive network packet monitoring using Scapy

\- Network flow tracking and visualization

\- Interactive cybersecurity dashboard

\- Model evaluation and comparison



\## Technology Stack



\- Python

\- Flask

\- Scapy

\- scikit-learn

\- pandas

\- NumPy

\- HTML, CSS, and JavaScript



\## Dataset



AIDAS uses the UNSW-NB15 intrusion detection dataset.



Dataset files are not included in this repository.



The project expects the following files:



\- `data/raw/UNSW\_NB15\_training-set.csv`

\- `data/raw/UNSW\_NB15\_testing-set.csv`



\## Project Structure



```text

AIDAS/

├── capture/

│   ├── application\_features.py

│   ├── flow\_tracker.py

│   └── live\_capture.py

├── dashboard/

│   ├── app.py

│   ├── evaluate\_models.py

│   ├── live\_monitor.py

│   ├── static/

│   └── templates/

├── experiments/

├── preprocessing/

├── reports/

├── tests/

├── requirements.txt

└── README.md

```



\## Installation



Create a virtual environment:



```bash

python -m venv .venv

```



Activate it on Windows PowerShell:



```powershell

.\\.venv\\Scripts\\Activate.ps1

```



Install dependencies:



```bash

python -m pip install -r requirements.txt

```



\## Running the Dashboard



After preparing the dataset and trained model artifacts:



```bash

python -m dashboard.app

```



Open the local dashboard at:



`http://127.0.0.1:5000`



\## Running Tests



```bash

python -m pytest tests -v

```



\## Model Evaluation



The project compares three supervised classifiers on the UNSW-NB15 official test split.



| Model | Accuracy | Macro-F1 |

|---|---:|---:|

| Logistic Regression | 67.65% | 0.3565 |

| Decision Tree | 72.53% | 0.5065 |

| Random Forest | 74.85% | 0.4726 |



Random Forest achieved the highest accuracy, while Decision Tree achieved the highest macro-F1.



These results should be interpreted with dataset overlap, class imbalance, and evaluation limitations in mind.



\## Unknown Attack Experiments



AIDAS includes controlled experiments in which selected attack categories are withheld during model training.



These experiments investigate whether anomaly scores or classification confidence can help distinguish withheld categories.



They do not establish reliable detection of previously unknown real-world attacks.



\## Live Network Monitoring



The dashboard supports passive packet capture and network flow visualization.



\*\*Important:\*\* Live packet capture is not equivalent to validated live ML attack detection. The current live feature extractor has not been established as semantically compatible with all UNSW-NB15 training features.



Only monitor networks and devices you are authorized to observe.



\## Limitations



\- Dataset-derived model predictions are not validated live-network predictions.

\- Trained models and datasets are not distributed in this repository.

\- Exact feature-vector overlap exists between some dataset splits.

\- Unknown-category experiments are exploratory, not proof of zero-day detection.

\- The Flask development server is intended for local academic demonstration.



\## Project Status



\- Machine learning experiments: Completed

\- Experimental unknown-category analysis: Completed

\- Flask dashboard: Completed

\- Interactive network visualization: Completed

\- Live packet monitoring: Functionally tested

\- Technical report and presentation: In progress



\## License



No license has been selected yet.
