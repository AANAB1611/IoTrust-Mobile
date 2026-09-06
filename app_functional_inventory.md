# IoTrust BLE Security - app.py Functional Inventory

## 1. Hardware Communication

- **Bluetooth Adapter Status Check**: Verifies if Bluetooth radio is available and powered on before scanning
- **Windows Native BLE Enumeration**: Uses WinRT API to enumerate known BLE devices from Windows Settings menu
- **Bleak Scanner Integration**: Performs active BLE scanning using bleak library for raw packet capture
- **Background Continuous Scanning**: Starts persistent background BLE scanning with automatic device cache updates
- **Signal Buffer Management**: Collects and maintains RSSI readings per device (5-packet buffer) for signal analysis
- **Manufacturer Data Parsing**: Extracts and parses manufacturer-specific advertisement data (Apple, Samsung, Huawei, Sony, Bose, Jabra)
- **Device Cache Management**: Maintains persistent device cache with timestamp tracking for stale device cleanup

## 2. Data Processing

- **RSSI Jitter Calculation**: Computes signal stability (standard deviation/variance) from buffered RSSI readings
- **UUID Entropy Calculation**: Measures Shannon entropy of service UUIDs to detect professional vs. simulated devices
- **Service Cardinality Counting**: Counts advertised BLE services per device
- **Advertisement Interval Tracking**: Monitors advertisement timing regularity
- **Packet Loss Rate Estimation**: Estimates packet loss from signal jitter metrics
- **Device Name Extraction**: Extracts and prioritizes local_name from advertisement data over device.name
- **Device Deduplication**: Deduplicates devices by name (keeps strongest RSSI) and by MAC address
- **Feature Extraction Pipeline**: Converts raw BLE scan data into ML-ready feature vectors (uuid_entropy, rssi_jitter, adv_interval, service_count, packet_loss_rate, device_name_encoded, mac_prefix_encoded)
- **Data Preprocessing**: Handles missing values (mean imputation) and label encoding for ML models
- **Brand Detection**: Identifies device brands (Apple, Samsung, Huawei, etc.) from advertisement names and manufacturer data

## 3. Security Auditing

- **Golden Database Management**: Loads and maintains verified device whitelist from Golden_Database.csv
- **Strict MAC Verification**: Performs exact MAC address matching against Golden Database (Tier 1 verification)
- **Tier 1 Verification**: Grants "VERIFIED GENUINE" status only to devices with exact MAC match in Golden Database
- **Tier 2 Behavioral Audit**: Performs full ML-based behavioral analysis for non-verified devices using:
  - LightGBM Classifier: Predicts device genuineness probability
  - Random Forest Classifier: Predicts device genuineness probability
  - Ensemble Scoring: Averages LGBM and RF probabilities for final score
- **Tier 3 Anomaly Detection**: Uses Isolation Forest to detect statistical anomalies in device behavior
- **Feature-Based Trust Adjustments**: Applies bonuses/penalties based on:
  - UUID Entropy (professional device bonus)
  - Service Cardinality (genuine device bonus / bare advertisement penalty)
  - RSSI Jitter (simulated clone penalty / unstable signal penalty)
  - Advertisement Interval (irregular interval penalty)
- **Dynamic Verdict Mapping**: Assigns verdicts based on ensemble score and anomaly detection:
  - VERIFIED GENUINE (Tier 1 - Blue Badge)
  - OPTIMIZED / GENUINE (Tier 2 - Green Badge)
  - UNVERIFIED / NEUTRAL (Tier 2 - Grey Badge)
  - SUSPICIOUS / ANOMALY (Tier 3 - Orange Badge)
- **Rationale Generation**: Builds human-readable explanations for trust score decisions
- **Golden Database CRUD**: Adds new devices to Golden Database via API endpoint

## 4. Web Connectivity

- **Flask Web Server**: Hosts REST API on 127.0.0.1:5000 with threaded mode
- **CORS Configuration**: Enables cross-origin requests from frontend dashboard
- **REST API Endpoints**:
  - `GET /scan_nearby`: Triggers 20-second BLE scan and returns discovered devices
  - `POST /start_background_scan`: Starts continuous background BLE scanning
  - `POST /audit`: Performs security audit on device data and returns trust score
  - `POST /add_to_golden_database`: Adds device to Golden Database whitelist
  - `GET /get_golden_database`: Returns all devices in Golden Database
  - `GET /health`: Health check endpoint
- **JSON Serialization**: Converts numpy types (int64, float64, arrays) and bytes to JSON-compatible Python types
- **Error Handling**: Returns structured error messages for Bluetooth issues (powered off, permission denied, adapter not found, timeout)
- **Request Logging**: Logs incoming audit requests with client IP and input data

## 5. Model Management

- **Model Loading**: Loads 5 pre-trained ML models from saved_models/ directory:
  - lgbm.joblib (LightGBM Classifier)
  - rf.joblib (Random Forest Classifier)
  - isof.joblib (Isolation Forest Anomaly Detector)
  - scaler.joblib (Feature StandardScaler)
  - device_name_le.joblib (Device Name Label Encoder)
  - mac_prefix_le.joblib (MAC Prefix Label Encoder)
- **Golden Database Loading**: Loads verified device whitelist from Golden_Database.csv at startup
- **Label Encoding**: Transforms categorical features (device_name, mac_prefix) to numerical values for ML models
- **Feature Scaling**: Standardizes numerical features using pre-trained scaler
- **Model Inference**: Runs LGBM and RF predictions on preprocessed feature vectors
- **Anomaly Scoring**: Computes anomaly probability from Isolation Forest decision function
- **Ensemble Prediction**: Combines multiple model outputs into single trust score

## 6. Environment & Dependency Management

- **Dependency Verification**: Checks for required Python packages (flask, flask-cors, bleak, scikit-learn, lightgbm, joblib, pandas, numpy) at startup
- **Missing Package Detection**: Identifies and reports missing dependencies with installation instructions
- **Platform Detection**: Adapts Bluetooth scanning strategy based on operating system (Windows vs. others)
- **Graceful Degradation**: Falls back to default values when models or databases fail to load
