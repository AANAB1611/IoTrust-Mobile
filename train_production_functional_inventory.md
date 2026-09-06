# IoTrust Production Training Pipeline - train_production.py Functional Inventory

## 1. Data Acquisition

- **Remote Dataset Download**: Downloads IoT-23 dataset files from CTU (Czech Technical University) servers using HTTP streaming
- **Chunked File Download**: Downloads large files in 8KB chunks with progress tracking and percentage display
- **Dataset Sources**: Loads three distinct datasets:
  - Dataset A (Genuine): CTU-Honeypot-Capture-5-1 (labeled as genuine)
  - Dataset B (Malicious): CTU-Honeypot-Capture-5-1 (labeled as malicious)
  - Dataset C (Mixed): CTU-IoT-Malware-Capture-34-1 (mixed/unknown labels)
- **IoT-23 Connection Log Parsing**: Parses tab-separated conn.log.labeled.txt files containing network flow data
- **Chunked Data Processing**: Reads large CSV files in 10,000-row chunks to handle memory constraints
- **Fallback Data Generation**: Generates synthetic benchmark data when remote downloads fail or parsing errors occur

## 2. Data Synthesis & Augmentation

- **Synthetic Genuine Device Generation**: Creates simulated genuine BLE device data with realistic characteristics:
  - Device names: AirPods, Galaxy, Huawei variants
  - MAC prefixes: 00:25:96, 20:AB, 78:85 (real manufacturer prefixes)
  - Low UUID entropy (2.0-2.8 bits)
  - Low RSSI jitter (0.5-2.9 dBm)
  - Regular advertisement intervals (100-300 ms)
  - High service count (3-8 services)
  - Low packet loss rate (0-5%)
- **Synthetic Malicious Device Generation**: Creates simulated attack device data:
  - Device names: Spoof, Clone, Relay variants
  - Random MAC prefixes: AA:BB:CC, BB:CC:DD
  - High UUID entropy (5.0-9.0 bits - indicating professional/sophisticated attacks)
  - High RSSI jitter (8.0-15.0 dBm - indicating software simulation)
  - Irregular advertisement intervals (400-800 ms)
  - Low service count (0-2 services - bare advertisements)
  - High packet loss rate (10-20%)
- **Mixed Device Generation**: Creates neutral/unknown device data with random labels (50/50 genuine/malicious split)
- **Network-to-BLE Feature Mapping**: Converts IoT-23 network flow features to BLE-like characteristics:
  - Duration → Advertisement Interval
  - Bytes transferred → Service Cardinality proxy
  - Connection state → Behavioral indicator
  - Traffic entropy → UUID Entropy proxy
  - Duration variance → RSSI Jitter proxy

## 3. Feature Engineering

- **Feature Extraction Pipeline**: Extracts 7 ML-ready features from raw data:
  - uuid_entropy: Shannon entropy of service UUIDs (professional device indicator)
  - rssi_jitter: Signal stability metric (physical vs. simulated indicator)
  - adv_interval: Advertisement timing regularity
  - service_count: Number of advertised BLE services
  - packet_loss_rate: Signal reliability metric
  - device_name_encoded: Label-encoded device name
  - mac_prefix_encoded: Label-encoded MAC prefix
- **Label Encoding**: Transforms categorical features (device_name, mac_prefix) to numerical values using LabelEncoder
- **Feature Scaling**: Standardizes numerical features using StandardScaler (zero mean, unit variance)
- **Missing Value Handling**: Replaces missing values with column means during preprocessing
- **Data Filtering**: Separates labeled data (genuine/malicious) from mixed/unknown data for supervised training

## 4. Algorithm Training (The Ensemble)

### LightGBM Classifier Training
- **Model Configuration**: 150 estimators, max depth 7, learning rate 0.08, min child samples 5
- **Training Data**: 80% of labeled dataset (genuine + malicious)
- **Binary Classification**: Predicts device genuineness probability (0=malicious, 1=genuine)
- **Probability Output**: Returns probability scores for both classes

### Random Forest Classifier Training
- **Model Configuration**: 150 estimators, max depth 12, min samples split 3, parallel processing (n_jobs=-1)
- **Training Data**: Same 80% split as LightGBM
- **Binary Classification**: Predicts device genuineness probability
- **Probability Output**: Returns probability scores for both classes

### Isolation Forest Anomaly Detection Training
- **Model Configuration**: 150 estimators, contamination=0.1 (10% expected anomalies)
- **Training Data**: Only genuine devices (label=1) - learns normal behavior patterns
- **Anomaly Detection**: Identifies statistical outliers from normal device behavior
- **Decision Function**: Returns anomaly scores (negative = anomaly, positive = normal)

### Ensemble Strategy
- **Dual Model Approach**: Uses both LightGBM and Random Forest for robust predictions
- **Averaging Ensemble**: Combines predictions by averaging probability scores from both classifiers
- **Anomaly Override**: Isolation Forest can flag devices as suspicious regardless of classifier output

## 5. Validation & Testing

- **Train/Test Split**: 80% training, 20% testing with random_state=42 for reproducibility
- **Accuracy Metrics**: Calculates 4 key performance metrics:
  - Accuracy: Overall correct predictions
  - Precision: True positives / (True positives + False positives)
  - Recall: True positives / (True positives + False negatives)
  - F1-Score: Harmonic mean of precision and recall
- **Model Comparison**: Side-by-side performance comparison of LightGBM vs. Random Forest
- **Feature Importance Analysis**: Displays LightGBM feature importances ranked by contribution
- **Market Certification**: Assigns certification status based on average accuracy:
  - APPROVED: Average accuracy ≥ 85%
  - PROVISIONAL: Average accuracy ≥ 70%
  - NEEDS IMPROVEMENT: Average accuracy < 70%
- **Validation Dataset**: Uses Dataset C (mixed/unknown) as independent test set

## 6. Model Serialization

- **LightGBM Model Export**: Saves trained LightGBM classifier to saved_models/lgbm.joblib
- **Random Forest Model Export**: Saves trained Random Forest classifier to saved_models/rf.joblib
- **Isolation Forest Model Export**: Saves trained anomaly detector to saved_models/isof.joblib
- **Scaler Export**: Saves feature StandardScaler to saved_models/scaler.joblib
- **Device Name Encoder Export**: Saves LabelEncoder for device names to saved_models/device_name_le.joblib
- **MAC Prefix Encoder Export**: Saves LabelEncoder for MAC prefixes to saved_models/mac_prefix_le.joblib
- **Joblib Serialization**: Uses joblib.dump() for efficient binary serialization of sklearn models
- **Directory Management**: Automatically creates saved_models/ directory if it doesn't exist

## 7. Environment & Dependency Management

- **Dependency Verification**: Checks for required Python packages (lightgbm, scikit-learn, joblib, pandas, numpy, requests) at startup
- **Missing Package Detection**: Identifies and reports missing dependencies with installation instructions
- **SSL Warning Suppression**: Disables SSL certificate verification warnings for IoT-23 dataset downloads
- **Directory Initialization**: Creates data/ and saved_models/ directories automatically
- **Error Handling**: Graceful fallback to synthetic data generation when remote downloads fail
