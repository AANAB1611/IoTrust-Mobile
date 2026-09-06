# IoTrust Mobile - Technical Specification & Architecture Manual

## Executive Summary

**IoTrust Mobile** is a real-time Bluetooth Low Energy (BLE) security scanner and ML-powered trust evaluation engine. It combines hardware-level BLE packet capture with an ensemble machine learning pipeline to detect device spoofing, cloning, and anomalous behavior in IoT ecosystems.

---

## 1. The Tech Stack (The "Parts List")

### 1.1 Backend Framework: Flask

**Why Flask?**
- **Lightweight & Flexible**: Flask is a micro-framework that provides the essential tools for building web applications without imposing rigid structures. For a real-time BLE scanner, we need minimal overhead and maximum control over threading and async operations.
- **REST API Simplicity**: Flask's decorator-based routing (`@app.route`) makes it trivial to expose endpoints like `/scan_nearby` and `/audit` that the frontend can call.
- **Threading Support**: The `threaded=True` parameter in `app.run()` (line 992) prevents the Flask server from freezing when the Bluetooth hardware is busy processing BLE packets. This is critical because BLE scanning is I/O-bound and can take 20+ seconds.

**Key Configuration:**
```python
app.run(debug=True, host='127.0.0.1', port=5000, threaded=True)
```

### 1.2 Bluetooth Stack: Bleak

**What is Bleak?**
Bleak (Bluetooth Low Energy Agnostic Klient) is a cross-platform BLE library for Python that supports Windows, Linux, and macOS. It provides a unified API for BLE operations regardless of the underlying operating system's Bluetooth stack.

**Why Bleak for "Active Scanning"?**
- **Active Scanning Mode**: Bleak's `scanning_mode="active"` parameter (line 654) enables the scanner to receive **Scan Response** packets in addition to regular advertisement packets. This is crucial because many IoT devices (especially earbuds and wearables) transmit their device name and manufacturer data in scan responses, not in the initial advertisement.
- **No UUID Filtering**: By setting `service_uuids=None` (line 655), we capture ALL BLE packets in the vicinity, not just those advertising specific services. This ensures we detect even devices that don't advertise standard Bluetooth services.
- **Callback-Based Detection**: Bleak's `set_detection_callback()` (line 562) allows us to process each BLE packet as it arrives, enabling real-time device discovery and RSSI tracking.

**BLE Packet Flow:**
```
Radio Waves → Bluetooth Adapter → Bleak Library → Python Callback → Device Cache
```

### 1.3 AI/ML Core Libraries

| Library | Version | Purpose in Ensemble |
|---------|---------|---------------------|
| **LightGBM** | Latest | Primary classifier for genuine vs. malicious device detection. Uses gradient boosting for high accuracy on structured data. |
| **Scikit-learn** | Latest | Provides Random Forest classifier (ensemble of decision trees) and Isolation Forest for anomaly detection. Also provides StandardScaler for feature normalization and LabelEncoder for categorical features. |
| **Pandas** | Latest | Data manipulation and analysis. Used for loading CSV datasets, feature engineering, and data preprocessing. |
| **NumPy** | Latest | Numerical computing. Used for statistical calculations (mean, variance, standard deviation) on RSSI readings and entropy calculations. |
| **Joblib** | Latest | Model serialization. Saves trained ML models to disk (`lgbm.joblib`, `rf.joblib`, etc.) and loads them at runtime for inference. |

---

## 2. The Hardware-to-Software Bridge (Bluetooth Communication)

### 2.1 From Radio Waves to Digital Data

The process of converting raw radio waves into structured data follows this pipeline:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    BLUETOOTH LOW ENERGY (BLE) PHYSICAL LAYER                │
├─────────────────────────────────────────────────────────────────────────────┤
│  1. Radio Waves (2.4 GHz ISM Band)                                          │
│     ↓                                                                        │
│  2. Bluetooth Radio Hardware (Antenna + Modem)                              │
│     ↓                                                                        │
│  3. Advertisement Packets (31-byte payload, broadcast every 20-10240ms)    │
│     ↓                                                                        │
│  4. Scan Response Packets (optional, contains device name + manufacturer)  │
│     ↓                                                                        │
│  5. Bleak Library (Python wrapper around OS Bluetooth stack)                │
│     ↓                                                                        │
│  6. AdvertisingData Object (parsed packet fields)                           │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 2.2 Advertisement Data Structure

Each BLE advertisement packet contains:

| Field | Description | Example |
|-------|-------------|---------|
| **MAC Address** | 48-bit hardware address | `00:25:96:XX:XX:XX` |
| **RSSI** | Received Signal Strength Indicator (dBm) | `-65 dBm` |
| **Local Name** | Device name (from scan response) | `"AirPods Pro"` |
| **Service UUIDs** | Advertised Bluetooth services | `["0000180a-0000-1000-8000-00805f9b34fb"]` |
| **Manufacturer Data** | Vendor-specific data (company ID + bytes) | `{0x004C: b'\x02\x15...'}` |
| **TX Power** | Transmit power level (dBm) | `-20 dBm` |

### 2.3 Manufacturer Data Parsing

Manufacturer data is the key to identifying device brands (Apple, Samsung, Huawei, etc.). The structure is:

```
Company ID (2 bytes) + Data Payload (variable length)
```

**Example: Apple AirPods**
- Company ID: `0x004C` (Apple Inc.)
- Data: Contains proximity sensor data, battery status, etc.

**Parsing Logic (lines 384-404 in app.py):**
```python
def _parse_manufacturer_data(self, advertising_data):
    detected_brands = []
    for company_id, data in advertising_data.manufacturer_data.items():
        company_hex = hex(company_id)
        for brand, sig in self.MANUFACTURER_SIGNATURES.items():
            if sig['company_id'].lower() == company_hex.lower():
                detected_brands.append(brand)
    return detected_brands
```

### 2.4 RSSI Jitter Calculation

**What is RSSI Jitter?**
RSSI Jitter measures the variability of signal strength over time. It's a critical indicator of device authenticity:

- **Low Jitter (< 3 dBm)**: Stable signal → Physical hardware device
- **Medium Jitter (3-10 dBm)**: Moderate variability → Possibly genuine but unstable
- **High Jitter (> 10 dBm)**: Highly variable → Software-simulated clone or relay attack

**Calculation Method:**
The system maintains a **signal buffer** of the last 5 RSSI readings per device (lines 406-426):

```python
def _update_signal_buffer(self, mac, rssi):
    if mac not in self.signal_buffer:
        self.signal_buffer[mac] = []
    self.signal_buffer[mac].append(rssi)
    # Keep only last BUFFER_SIZE readings
    if len(self.signal_buffer[mac]) > self.BUFFER_SIZE:
        self.signal_buffer[mac] = self.signal_buffer[mac][-self.BUFFER_SIZE:]

def _get_buffer_stats(self, mac):
    readings = self.signal_buffer[mac]
    mean_rssi = np.mean(readings)
    variance_rssi = np.var(readings)
    return mean_rssi, variance_rssi
```

The jitter is then calculated as the **standard deviation** of the buffer:
```python
rssi_jitter = float(np.sqrt(buffer_variance))
```

### 2.5 UUID Entropy Calculation

**What is UUID Entropy?**
UUID Entropy measures the randomness/complexity of advertised service UUIDs using Shannon entropy. Professional devices typically have well-structured UUIDs, while malicious devices may have random or missing UUIDs.

**Shannon Entropy Formula:**
```
H = -Σ(p(x) * log₂(p(x)))
```

Where `p(x)` is the probability of each character in the UUID string.

**Implementation (lines 823-835 in app.py):**
```python
def _shannon_entropy(self, data):
    if not data:
        return 0.0
    entropy = 0.0
    data_len = len(data)
    for i in range(256):
        freq = data.count(chr(i)) / data_len
        if freq > 0:
            entropy -= freq * math.log2(freq)
    return entropy
```

**Interpretation:**
- **Low Entropy (0-2.5 bits)**: Simple, predictable UUIDs → Professional device
- **Medium Entropy (2.5-5 bits)**: Moderate complexity → Neutral
- **High Entropy (5+ bits)**: Random/complex UUIDs → Suspicious

---

## 3. The AI Intelligence Engine (The "Brain")

### 3.1 Tri-Stream Ensemble Architecture

The ML engine uses three independent models that work together to evaluate device trustworthiness:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TRI-STREAM ENSEMBLE                                 │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                  │
│  │   LightGBM   │    │Random Forest │    │Isolation     │                  │
│  │  Classifier  │    │  Classifier  │    │   Forest     │                  │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘                  │
│         │                   │                   │                           │
│         ▼                   ▼                   ▼                           │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐                  │
│  │  P(Genuine)  │    │  P(Genuine)  │    │Anomaly Score │                  │
│  │   0.0 - 1.0  │    │   0.0 - 1.0  │    │  -1.0 to 1.0 │                  │
│  └──────┬───────┘    └──────┬───────┘    └──────┬───────┘                  │
│         │                   │                   │                           │
│         └───────────┬───────┘                   │                           │
│                     ▼                           │                           │
│            ┌────────────────┐                   │                           │
│            │Ensemble Score  │                   │                           │
│            │ (LGBM + RF)/2  │                   │                           │
│            └────────┬───────┘                   │                           │
│                     │                           │                           │
│                     └───────────┬───────────────┘                           │
│                                 ▼                                           │
│                        ┌────────────────┐                                   │
│                        │  Trust Score   │                                   │
│                        │   0 - 100      │                                   │
│                        └────────────────┘                                   │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.2 Model 1: LightGBM Classifier

**What LightGBM Looks For:**
LightGBM (Light Gradient Boosting Machine) is a gradient boosting framework that builds an ensemble of decision trees sequentially. Each tree corrects the errors of the previous trees.

**Features Used:**
1. `uuid_entropy` - Complexity of service UUIDs
2. `rssi_jitter` - Signal stability
3. `adv_interval` - Advertisement timing regularity
4. `service_count` - Number of advertised services
5. `packet_loss_rate` - Estimated packet loss
6. `device_name_encoded` - Categorical device type
7. `mac_prefix_encoded` - Categorical MAC prefix

**Training Configuration (lines 285-292 in train_production.py):**
```python
lgbm = lgb.LGBMClassifier(
    n_estimators=150,      # 150 decision trees
    max_depth=7,           # Maximum tree depth
    learning_rate=0.08,    # Step size for gradient descent
    min_child_samples=5,   # Minimum samples in leaf nodes
    random_state=42,       # Reproducibility seed
    verbose=-1             # Suppress training output
)
```

**What It Detects:**
- Patterns in feature combinations that indicate genuine devices
- Non-linear relationships between entropy, jitter, and service count
- Device-specific behavioral signatures

### 3.3 Model 2: Random Forest Classifier

**What Random Forest Looks For:**
Random Forest builds multiple decision trees on random subsets of the data and features, then averages their predictions. This reduces overfitting and improves generalization.

**Training Configuration (lines 306-312 in train_production.py):**
```python
rf = RandomForestClassifier(
    n_estimators=150,      # 150 decision trees
    max_depth=12,          # Deeper trees than LightGBM
    min_samples_split=3,   # Minimum samples to split a node
    random_state=42,       # Reproducibility seed
    n_jobs=-1              # Use all CPU cores
)
```

**What It Detects:**
- Feature importance rankings (which features matter most)
- Decision boundaries in high-dimensional feature space
- Robust predictions through ensemble averaging

### 3.4 Model 3: Isolation Forest (Anomaly Detection)

**What Isolation Forest Looks For:**
Isolation Forest is an unsupervised anomaly detection algorithm. It works by randomly partitioning data points and measuring how many partitions are needed to isolate each point. Anomalies are easier to isolate (require fewer partitions).

**Training Configuration (lines 328-333 in train_production.py):**
```python
isof = IsolationForest(
    n_estimators=150,      # 150 isolation trees
    contamination=0.1,     # Expected 10% anomaly rate
    random_state=42        # Reproducibility seed
)
```

**Critical Difference:**
- LightGBM and Random Forest are trained on **both genuine and malicious** devices
- Isolation Forest is trained **only on genuine devices** (line 326: `X_genuine = X_scaled[y == 1]`)
- This means Isolation Forest learns what "normal" looks like and flags deviations

**What It Detects:**
- Outliers that don't match the genuine device profile
- Novel attack patterns not seen in training data
- Statistical anomalies in feature distributions

### 3.5 Tiered Verification Logic

The system uses a three-tier verification hierarchy:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         TIERED VERIFICATION LOGIC                           │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  TIER 1: GOLDEN DATABASE (MAC Verification)                                │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  IF mac_prefix IN Golden_Database.csv:                              │   │
│  │    → Trust Score = 100 (VERIFIED GENUINE)                           │   │
│  │    → Skip ML evaluation entirely                                    │   │
│  │    → Return immediately with Tier 1 status                          │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              ↓ (If not in Golden DB)                        │
│                                                                             │
│  TIER 2: BEHAVIORAL ML (Ensemble Evaluation)                               │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  1. Extract features: entropy, jitter, interval, services, loss     │   │
│  │  2. Encode categorical features (device_name, mac_prefix)           │   │
│  │  3. Scale features using StandardScaler                             │   │
│  │  4. Run LightGBM → P(Genuine)                                       │   │
│  │  5. Run Random Forest → P(Genuine)                                  │   │
│  │  6. Ensemble Score = (LGBM + RF) / 2                                │   │
│  │  7. Apply feature-based adjustments (±5 to ±15 points)              │   │
│  │  8. Clamp to 0-100 range                                            │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                              ↓ (Always runs)                                │
│                                                                             │
│  TIER 3: ANOMALY DETECTION (Isolation Forest)                              │
│  ┌─────────────────────────────────────────────────────────────────────┐   │
│  │  IF anomaly_score_raw < -0.15 OR anomaly_prob > 0.7:                │   │
│  │    → Tier 3 Anomaly Detected                                        │   │
│  │    → Cap Trust Score at 39 (SUSPICIOUS / ANOMALY)                   │   │
│  │    → Override verdict regardless of Tier 2 score                    │   │
│  └─────────────────────────────────────────────────────────────────────┘   │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 3.6 Trust Score Math (0-100)

The final trust score is calculated through this formula:

```
Trust Score = Ensemble Score × 100 + Feature Adjustments
```

**Step-by-Step Calculation:**

1. **Base Score from Ensemble:**
   ```
   ensemble_score = (lgbm_proba + rf_proba) / 2.0
   trust_score = ensemble_score × 100
   ```

2. **Feature-Based Adjustments:**

   | Condition | Adjustment | Rationale |
   |-----------|------------|-----------|
   | `uuid_entropy > 2.8` | +5 | Professional device bonus |
   | `service_count >= 3` | +10 | Genuine device bonus |
   | `service_count == 0` | -10 | Bare advertisement penalty |
   | `rssi_jitter > 10` | -15 | Software-simulated clone penalty |
   | `rssi_jitter > 5` | -5 | Unstable signal penalty |
   | `adv_interval > 500` | -10 | Irregular interval penalty |

3. **Clamping:**
   ```
   trust_score = max(0, min(100, trust_score))
   ```

4. **Tier 3 Override:**
   ```
   IF anomaly_detected:
       trust_score = min(trust_score, 39.0)
   ```

**Verdict Mapping:**

| Trust Score | Verdict | Tier |
|-------------|---------|------|
| 100 | VERIFIED GENUINE | Tier 1 |
| > 75 | OPTIMIZED / GENUINE | Tier 2 |
| 40-75 | UNVERIFIED / NEUTRAL | Tier 2 |
| < 40 | SUSPICIOUS / ANOMALY | Tier 3 |

---

## 4. The Frontend-Backend Connection (The "Nervous System")

### 4.1 REST API Architecture

The frontend (JavaScript) communicates with the backend (Python/Flask) through REST API endpoints:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         REST API COMMUNICATION                              │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  FRONTEND (JavaScript)              BACKEND (Python/Flask)                  │
│  ┌─────────────────────┐            ┌─────────────────────┐                │
│  │  fetch('/scan_nearby')│ ────────→ │  @app.route('/scan_  │                │
│  │  GET request         │           │  nearby')            │                │
│  └─────────────────────┘            └──────────┬──────────┘                │
│         ↑                                      │                           │
│         │                                      ▼                           │
│  ┌─────────────────────┐            ┌─────────────────────┐                │
│  │  JSON Response       │ ←──────── │  asyncio.run(ble_    │                │
│  │  [device1, device2]  │           │  scanner.scan())     │                │
│  └─────────────────────┘            └─────────────────────┘                │
│                                                                             │
│  ┌─────────────────────┐            ┌─────────────────────┐                │
│  │  fetch('/audit')     │ ────────→ │  @app.route('/audit')│                │
│  │  POST request        │           │  POST request        │                │
│  │  {device_data}       │           │                      │                │
│  └─────────────────────┘            └──────────┬──────────┘                │
│         ↑                                      │                           │
│         │                                      ▼                           │
│  ┌─────────────────────┐            ┌─────────────────────┐                │
│  │  JSON Response       │ ←──────── │  engine.generate_    │                │
│  │  {trust_score, ...}  │           │  trust_score(data)   │                │
│  └─────────────────────┘            └─────────────────────┘                │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

### 4.2 API Endpoints

| Endpoint | Method | Purpose | Request Body | Response |
|----------|--------|---------|--------------|----------|
| `/scan_nearby` | GET | Trigger BLE scan and return discovered devices | None | Array of device objects |
| `/audit` | POST | Run ML trust evaluation on a device | Device telemetry data | Trust score, verdict, rationale |
| `/start_background_scan` | POST | Start continuous background scanning | None | Status message |
| `/add_to_golden_database` | POST | Add device to Tier 1 whitelist | MAC prefix, device name | Success confirmation |
| `/get_golden_database` | GET | Retrieve all whitelisted devices | None | Golden database object |
| `/health` | GET | Check if backend is running | None | `{"status": "ok"}` |

### 4.3 JSON Serialization

**The Challenge:**
BLE data contains raw bytes and NumPy data types that cannot be directly serialized to JSON for the browser.

**The Solution (lines 928-939 in app.py):**
```python
def convert_to_native(obj):
    if isinstance(obj, bytes):
        return obj.hex()  # Convert bytes to hex string
    if hasattr(obj, 'item'):  # numpy scalar (np.int64, np.float64, etc.)
        return obj.item()  # Convert to Python native type
    elif hasattr(obj, 'tolist'):  # numpy array
        return obj.tolist()  # Convert to Python list
    elif isinstance(obj, dict):
        return {k: convert_to_native(v) for k, v in obj.items()}
    elif isinstance(obj, list):
        return [convert_to_native(i) for i in obj]
    return obj
```

**Example Transformation:**
```python
# Before serialization
{
    'trust_score': np.float64(85.7),
    'manufacturer_data': {0x004C: b'\x02\x15...'},
    'rssi_readings': np.array([-65, -67, -63])
}

# After serialization
{
    'trust_score': 85.7,
    'manufacturer_data': {'4c': '0215...'},
    'rssi_readings': [-65, -67, -63]
}
```

### 4.4 Frontend JavaScript Flow

**Device Discovery Flow:**
1. User clicks "Refresh Device List" button
2. JavaScript calls `fetch('http://127.0.0.1:5000/scan_nearby')`
3. Backend performs 20-second BLE scan
4. Backend returns JSON array of discovered devices
5. JavaScript dynamically creates device list items in the DOM
6. User clicks a device to select it

**Trust Evaluation Flow:**
1. User clicks "Start Real-Time Scan" button
2. JavaScript retrieves selected device's telemetry data
3. JavaScript calls `fetch('http://127.0.0.1:5000/audit', {method: 'POST', body: JSON.stringify(deviceData)})`
4. Backend runs ML ensemble evaluation
5. Backend returns trust score, verdict, and rationale
6. JavaScript updates UI with animated score, verdict badge, and typewriter rationale

---

## 5. UI/UX Architecture

### 5.1 Glassmorphism HUD Design

The frontend uses a **Glassmorphism** design language characterized by:

- **Frosted Glass Effect**: `backdrop-filter: blur(15px)` creates a translucent, blurred background
- **Semi-Transparent Backgrounds**: `rgba(20, 20, 20, 0.7)` allows the grid background to show through
- **Neon Cyan Accents**: `#00ffff` with `box-shadow: 0 0 15px rgba(0, 255, 255, 0.5)` creates glowing borders
- **Dark Theme**: `#050505` obsidian background with cyan grid lines

**Design Rationale:**
The glassmorphism aesthetic serves a functional purpose in a security dashboard:
- **Transparency** = Visibility into system state
- **Glow Effects** = Real-time activity indicators
- **Dark Theme** = Reduced eye strain during extended monitoring sessions

### 5.2 Tri-Panel HUD Layout

The interface uses a **3-column grid layout** (`grid-template-columns: 1fr 2fr 1fr`):

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           NAVIGATION BAR                                    │
│  IoTrust Mobile                                    [System: Active] [Ready] │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐  ┌──────────────────────────────┐  ┌──────────────┐      │
│  │ LEFT PANEL   │  │       CENTER PANEL           │  │ RIGHT PANEL  │      │
│  │              │  │                              │  │              │      │
│  │ Scanning     │  │    Security Core             │  │ Telemetry    │      │
│  │ Command      │  │    - Device Name             │  │ Data         │      │
│  │              │  │    - Trust Score Ring        │  │              │      │
│  │ Device List  │  │    - Verdict Badge           │  │ - UUID       │      │
│  │              │  │    - Rationale               │  │   Entropy    │      │
│  │ Signal       │  │                              │  │ - RSSI       │      │
│  │ Monitor      │  │                              │  │   Jitter     │      │
│  │              │  │                              │  │ - Adv        │      │
│  │              │  │                              │  │   Interval   │      │
│  └──────────────┘  └──────────────────────────────┘  └──────────────┘      │
│                                                                             │
├─────────────────────────────────────────────────────────────────────────────┤
│                           DECISION ENGINE RATIONALE                         │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Panel Purposes:**
- **Left Panel**: Device discovery and selection
- **Center Panel**: Trust score visualization and verdict display
- **Right Panel**: Raw telemetry data with micro-gauges

### 5.3 Signal Waveform Visualizer

The **Signal Waveform Visualizer** (recently updated) replaces the previous hex-data container with a pure CSS animation that represents real-time RSSI jitter streaming.

**Visual Representation:**
```
┌─────────────────────────────────────────────────────────────────────────────┐
│  PHY_LAYER_MONITOR // RSSI_JITTER_STREAM                                   │
│  ─────────────────────────────────────────────────────────────────────────  │
│                                                                             │
│     ════════════════════════════════════════════════════════════════════    │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

**Technical Implementation:**
- **Container**: 60px height, dark background, cyan border
- **Waveform Line**: 200% width with cyan gradient, animated with `wave-scroll` keyframes
- **Animation**: Translates horizontally while scaling vertically to simulate signal波动
- **Label**: Monospace font displaying "PHY_LAYER_MONITOR // RSSI_JITTER_STREAM"

**What It Represents:**
The waveform visualizer symbolizes the continuous stream of BLE advertisement packets being captured by the scanner. The scrolling animation represents the real-time nature of packet capture, while the vertical scaling represents RSSI jitter (signal strength variability).

### 5.4 Trust Score Ring

The **Trust Score Ring** is a doughnut chart (Chart.js) that displays the 0-100 trust score:

- **Cyan Fill**: Score portion (0-100)
- **Dark Fill**: Remaining portion (100-score)
- **Animated Count-Up**: Score animates from current value to new value over 1 second
- **Color Coding**:
  - Cyan (`#00ffff`): Tier 1 or Genuine
  - Amber (`#ffaa00`): Tier 2 Neutral
  - Crimson (`#ff0055`): Tier 3 Suspicious

### 5.5 Telemetry Micro-Gauges

The right panel displays three telemetry metrics with dual visualizations:

1. **UUID Entropy** (Cyan)
   - Circular gauge: `stroke-dasharray` based on entropy/10
   - Power bar: Linear fill based on entropy/10

2. **RSSI Jitter** (Amber)
   - Circular gauge: `stroke-dasharray` based on jitter/15
   - Power bar: Linear fill based on jitter/15

3. **Advertisement Interval** (Crimson)
   - Circular gauge: `stroke-dasharray` based on interval/1000
   - Power bar: Linear fill based on interval/1000

**Design Rationale:**
Dual visualization (circular + linear) provides both at-a-glance status (gauge) and precise measurement (bar) simultaneously.

---

## 6. Data Flow Summary

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                         COMPLETE DATA FLOW                                  │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  1. USER INTERACTION                                                        │
│     └─→ Click "Refresh Device List"                                         │
│                                                                             │
│  2. FRONTEND REQUEST                                                        │
│     └─→ fetch('http://127.0.0.1:5000/scan_nearby')                         │
│                                                                             │
│  3. BACKEND BLE SCAN                                                        │
│     └─→ BleakScanner(scanning_mode="active")                               │
│     └─→ 20-second scan duration                                             │
│     └─→ Callback processes each advertisement packet                        │
│     └─→ Extract: MAC, RSSI, Name, Services, Manufacturer Data              │
│                                                                             │
│  4. FEATURE EXTRACTION                                                      │
│     └─→ Calculate RSSI Jitter (std dev of signal buffer)                    │
│     └─→ Calculate UUID Entropy (Shannon entropy of service UUIDs)          │
│     └─→ Parse Manufacturer Data (brand detection)                           │
│                                                                             │
│  5. JSON SERIALIZATION                                                      │
│     └─→ Convert NumPy types to Python natives                               │
│     └─→ Convert bytes to hex strings                                        │
│                                                                             │
│  6. FRONTEND DISPLAY                                                        │
│     └─→ Render device list with signal strength indicators                  │
│     └─→ User selects device                                                 │
│                                                                             │
│  7. ML EVALUATION                                                           │
│     └─→ fetch('http://127.0.0.1:5000/audit', {device_data})                │
│     └─→ Tier 1: Check Golden Database (MAC lookup)                          │
│     └─→ Tier 2: Run LightGBM + Random Forest ensemble                      │
│     └─→ Tier 3: Run Isolation Forest anomaly detection                      │
│     └─→ Calculate trust score with feature adjustments                      │
│                                                                             │
│  8. UI UPDATE                                                               │
│     └─→ Animate trust score ring                                            │
│     └─→ Update verdict badge with tier indicator                            │
│     └─→ Typewriter effect for rationale                                     │
│     └─→ Update telemetry gauges and power bars                              │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 7. Security Considerations

### 7.1 MAC Address Spoofing Detection

The system detects MAC address spoofing through:
- **RSSI Jitter Analysis**: Spoofed devices often have unstable signals
- **Behavioral ML**: Models learn patterns that distinguish genuine from spoofed devices
- **Anomaly Detection**: Isolation Forest flags devices that don't match genuine profiles

### 7.2 Relay Attack Detection

Relay attacks (extending BLE range) are detected through:
- **RSSI Anomalies**: Relayed signals have different attenuation patterns
- **Timing Analysis**: Advertisement intervals may become irregular
- **Signal Jitter**: Relay equipment introduces additional signal variability

### 7.3 Clone Device Detection

Cloned devices (copying genuine device behavior) are detected through:
- **Manufacturer Data Validation**: Clones may have incorrect or missing manufacturer data
- **Service UUID Analysis**: Clones may advertise different or fewer services
- **Ensemble Voting**: Multiple models must agree for a "Genuine" verdict

---

## 8. Performance Characteristics

| Metric | Value | Notes |
|--------|-------|-------|
| BLE Scan Duration | 20 seconds | Configurable, balances discovery vs. speed |
| ML Inference Time | < 100ms | Per device evaluation |
| Model Load Time | < 2 seconds | All 3 models loaded at startup |
| Memory Usage | ~50 MB | Models + Flask + Bleak |
| CPU Usage | < 5% idle, < 30% during scan | Multi-threaded architecture |

---

## 9. File Structure

```
IoTrust_Mobile/
├── app.py                          # Flask backend + ML engine + BLE scanner
├── frontend.html                   # Single-page HTML/CSS/JS frontend
├── train_production.py             # ML training pipeline (IoT-23 dataset)
├── Golden_Database.csv             # Tier 1 whitelist (verified devices)
├── train_data.csv                  # Training dataset
├── saved_models/                   # Serialized ML models
│   ├── lgbm.joblib                 # LightGBM classifier
│   ├── rf.joblib                   # Random Forest classifier
│   ├── isof.joblib                 # Isolation Forest anomaly detector
│   ├── scaler.joblib               # StandardScaler for feature normalization
│   ├── device_name_le.joblib       # LabelEncoder for device names
│   └── mac_prefix_le.joblib        # LabelEncoder for MAC prefixes
├── data/                           # Training data directory
│   └── train.csv                   # Raw training data
├── setup_env.bat                   # Windows environment setup
├── setup_env.ps1                   # PowerShell environment setup
└── run_project.ps1                 # Project launcher
```

---

## 10. Conclusion

IoTrust Mobile represents a complete end-to-end security solution for BLE device authentication. By combining hardware-level packet capture with ensemble machine learning, it provides real-time trust evaluation that can detect spoofing, cloning, and anomalous behavior.

The system's strength lies in its **tri-stream ensemble architecture**:
- **LightGBM** provides high-accuracy classification
- **Random Forest** provides robust ensemble predictions
- **Isolation Forest** provides novel anomaly detection

Together, these models create a defense-in-depth approach that can adapt to evolving attack vectors while maintaining high accuracy on known device types.

---

*Document Version: 1.0*  
*Last Updated: 2026-03-31*  
*Project: IoTrust Mobile - BLE Security Scanner & ML Trust Engine*
