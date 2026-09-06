# CHAPTER 5.1: PSEUDO-CODE FOR IOTRUST ENGINE

---

## Phase 1: Signal Acquisition

```algorithm
BEGIN BLE_SCAN(duration)
    // Initialize BLE Scanner with Active Mode
    SET scanner = new BleakScanner(scanning_mode="active")
    SET devices = {}           // Device cache
    SET signal_buffer = {}     // RSSI buffer per device
    SET BUFFER_SIZE = 5      

    // Define Detection Callback
    FUNCTION on_advertisement(device, advertising_data)
        SET mac = device.address
        SET rssi = advertising_data.rssi
        SET local_name = advertising_data.local_name
        SET service_uuids = advertising_data.service_uuids

        // Update Signal Buffer
        IF NOT mac IN signal_buffer THEN
            signal_buffer[mac] = []
        END IF

        APPEND rssi TO signal_buffer[mac]
        IF LENGTH(signal_buffer[mac]) > BUFFER_SIZE THEN
            REMOVE FIRST ELEMENT FROM signal_buffer[mac]
        END IF

        // Cache Device
        devices[mac] = {
            'mac_address': mac,
            'local_name': local_name,
            'rssi': rssi,
            'service_uuids': service_uuids,
            'mac_prefix': EXTRACT_PREFIX(mac)
        }
    END FUNCTION

    scanner.set_detection_callback(on_advertisement)

    // Begin Scanning
    scanner.start()
    WAIT(duration)          // Scan for specified duration (e.g., 20 seconds)
    scanner.stop()

    RETURN devices
END BLE_SCAN
```

---

## Phase 2: Feature Engineering

```algorithm
BEGIN CALCULATE_FEATURES(device_data)
    SET rssi_jitter = 0.0
    SET uuid_entropy = 0.0

    // ----------------------------------------
    // RSSI Jitter Calculation (Standard Deviation)
    // ----------------------------------------
    SET readings = signal_buffer[device_data.mac_address]
    IF LENGTH(readings) >= 2 THEN
        SET mean = AVERAGE(readings)
        SET variance = AVERAGE((readings[i] - mean)²)
        SET rssi_jitter = SQRT(variance)
    END IF

    // ----------------------------------------
    // UUID Entropy Calculation (Shannon)
    // ----------------------------------------
    SET uuid_string = CONCATENATE(device_data.service_uuids)
    IF LENGTH(uuid_string) > 0 THEN
        SET entropy = 0.0
        FOR i = 0 TO 255 DO
            SET freq = COUNT_CHAR(uuid_string, CHAR(i)) / LENGTH(uuid_string)
            IF freq > 0 THEN
                SET entropy = entropy - (freq × LOG2(freq))
            END IF
        END FOR
        SET uuid_entropy = entropy
    ELSE
        SET uuid_entropy = 0.0
    END IF

    RETURN {
        'rssi_jitter': rssi_jitter,
        'uuid_entropy': uuid_entropy,
        'service_count': LENGTH(device_data.service_uuids)
    }
END CALCULATE_FEATURES
```

---

## Phase 3: Multi-Tier Inference

```algorithm
BEGIN GENERATE_TRUST_SCORE(device_data)
    SET features = CALCULATE_FEATURES(device_data)

    // ----------------------------------------
    // TIER 1: Golden Database Lookup
    // ----------------------------------------
    IF device_data.mac_prefix IN golden_database THEN
        RETURN {
            'trust_score': 100.0,
            'verdict': 'VERIFIED GENUINE',
            'tier': 1,
            'rationale': 'Whitelisted in Golden Database'
        }
    END IF

    // ----------------------------------------
    // Feature Scaling
    // ----------------------------------------
    SET X_scaled = scaler.transform(features)

    // ----------------------------------------
    // TIER 2: LightGBM Inference
    // ----------------------------------------
    SET lgbm_proba = lgbm_model.predict_proba(X_scaled)[0][1]
    // Returns P(genuine) in range [0.0, 1.0]

    // ----------------------------------------
    // TIER 2: Random Forest Inference
    // ----------------------------------------
    SET rf_proba = rf_model.predict_proba(X_scaled)[0][1]
    // Returns P(genuine) in range [0.0, 1.0]

    // Ensemble Score
    SET ensemble_score = (lgbm_proba + rf_proba) / 2.0

    // ----------------------------------------
    // TIER 3: Isolation Forest Anomaly Detection
    // ----------------------------------------
    SET anomaly_score_raw = isof_model.decision_function(X_scaled)[0]
    // Returns: -1.0 (anomalous) to +1.0 (normal)

    // Convert to Probability using Sigmoid
    SET anomaly_prob = 1.0 / (1.0 + EXP(anomaly_score_raw))

    // ----------------------------------------
    // Base Trust Calculation
    // ----------------------------------------
    SET trust_score = ensemble_score × 100

    // Feature Adjustments
    IF features.uuid_entropy > 2.8 THEN
        SET trust_score = trust_score + 5      // Professional device bonus
    END IF

    IF features.service_count >= 3 THEN
        SET trust_score = trust_score + 10     // Multiple services bonus
    ELSE IF features.service_count == 0 THEN
        SET trust_score = trust_score - 10     // Bare advertisement penalty
    END IF

    IF features.rssi_jitter > 10 THEN
        SET trust_score = trust_score - 15     // Clone/simulation penalty
    ELSE IF features.rssi_jitter > 5 THEN
        SET trust_score = trust_score - 5      // Unstable signal penalty
    END IF

    // Clamp to Valid Range
    SET trust_score = MAX(0, MIN(100, trust_score))

    // ----------------------------------------
    // TIER 3 ANOMALY OVERRIDE (CRITICAL)
    // ----------------------------------------
    SET tier3_detected = FALSE
    IF (anomaly_score_raw < -0.15) OR (anomaly_prob > 0.7) THEN
        SET tier3_detected = TRUE
        SET trust_score = MIN(trust_score, 39.0)   // Cap at 39.0
    END IF

    RETURN {
        'trust_score': trust_score,
        'ensemble_score': ensemble_score,
        'lgbm_proba': lgbm_proba,
        'rf_proba': rf_proba,
        'anomaly_score': anomaly_prob,
        'tier3_anomaly': tier3_detected
    }
END GENERATE_TRUST_SCORE
```

---

## Phase 4: Verdict Mapping

```algorithm
BEGIN MAP_VERDICT(trust_result)
    SET score = trust_result.trust_score
    SET tier3 = trust_result.tier3_anomaly
    SET rationale = []

    // Generate Rationale
    IF tier3 THEN
        APPEND 'Tier 3 Anomaly Detected' TO rationale
    END IF

    IF trust_result.features.uuid_entropy > 2.8 THEN
        APPEND 'High UUID Entropy (Professional)' TO rationale
    END IF

    IF trust_result.features.service_count >= 3 THEN
        APPEND 'High Service Cardinality' TO rationale
    END IF

    IF trust_result.features.rssi_jitter > 10 THEN
        APPEND 'High RSSI Jitter (Simulated)' TO rationale
    END IF

    // Verdict Categories
    IF tier3 == TRUE THEN
        SET verdict = 'SUSPICIOUS / ANOMALY'
        SET tier = 3
    ELSE IF score >= 75 THEN
        SET verdict = 'OPTIMIZED / GENUINE'
        SET tier = 2
    ELSE IF score >= 40 THEN
        SET verdict = 'UNVERIFIED / NEUTRAL'
        SET tier = 2
    ELSE
        SET verdict = 'SUSPICIOUS / ANOMALY'
        SET tier = 2
    END IF

    RETURN {
        'trust_score': score,
        'verdict': verdict,
        'tier': tier,
        'rationale': JOIN(rationale, '; ')
    }
END MAP_VERDICT
```

---

## Complete Algorithm Flow

```
┌─────────────────────────────────────────────────────────────┐
│           IoTrust Mobile Processing Pipeline              │
├──────────────────────────��──────────────────────────── │

│ BEGIN Main Pipeline                                │
│                                                 │
│   // Phase 1: Signal Acquisition                 │
│   devices = BLE_SCAN(duration=20)               │
│                                                 │
│   FOR EACH device IN devices DO                 │
│                                                 │
│     // Phase 2: Feature Engineering            │
│     features = CALCULATE_FEATURES(device)        │
│                                                 │
│     // Phase 3: Multi-Tier Inference            │
│     result = GENERATE_TRUST_SCORE(features)      │
│                                                 │
│     // Phase 4: Verdict Mapping                  │
│     verdict = MAP_VERDICT(result)               │
│                                                 │
│     DISPLAY(verdict)                          │
│   END FOR                                      │
│                                                 │
│ END Main Pipeline                              │
└─────────────────────────────────────────────────────────────┘
```

---

**Summary of Key Thresholds:**

| Parameter | Threshold | Effect |
|-----------|-----------|--------|
| UUID Entropy | > 2.8 | +5 trust |
| Service Count | >= 3 | +10 trust |
| Service Count | == 0 | -10 trust |
| RSSI Jitter | > 10 | -15 trust |
| RSSI Jitter | > 5 | -5 trust |
| Anomaly Score Raw | < -0.15 | Override cap at 39 |
| Anomaly Probability | > 0.7 | Override cap at 39 |

**Verdict Mapping:**

| Trust Score | Verdict | Tier |
|------------|---------|------|
| 100 | VERIFIED GENUINE | Tier 1 |
| > 75 | OPTIMIZED / GENUINE | Tier 2 |
| 40 - 74 | UNVERIFIED / NEUTRAL | Tier 2 |
| < 40 | SUSPICIOUS / ANOMALY | Tier 2 or 3 |