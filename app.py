#!/usr/bin/env python3
"""
IoTrust - BLE Security Scanner & ML Trust Engine
=======================================================================
Environment Setup: Run setup_env.bat or manually install:
  pip install flask flask-cors bleak pandas numpy joblib scikit-learn lightgbm
"""

# =============================================================================
# DEPENDENCY SELF-CHECK
# =============================================================================
import sys

REQUIRED_PACKAGES = {
    'flask': 'flask',
    'flask-cors': 'flask_cors',
    'bleak': 'bleak',
    'scikit-learn': 'sklearn',
    'lightgbm': 'lightgbm',
    'joblib': 'joblib',
    'pandas': 'pandas',
    'numpy': 'numpy'
}

_missing = []
for pkg_name, import_name in REQUIRED_PACKAGES.items():
    try:
        __import__(import_name)
    except ImportError:
        _missing.append(pkg_name)

if _missing:
    print("\n" + "="*60)
    print("*** MISSING DEPENDENCIES ***")
    print("="*60)
    print("The following packages are required but not installed:")
    print()
    for pkg in _missing:
        print(f"  * {pkg}")
    print()
    print(">>> Run this command to install:")
    print(f"    pip install {' '.join(_missing)}")
    print()
    print("Or run: setup_env.bat")
    print("="*60 + "\n")
    sys.exit(1)

# =============================================================================
# IMPORTS
# =============================================================================
# Standard library
import sys
import os
import json
import math
import asyncio
import threading
import logging

# Third-party: Data & ML
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

# Third-party: BLE scanning
from bleak import BleakScanner

# Third-party: Web framework
from flask import Flask, request, jsonify
from flask_cors import CORS


# =============================================================================
# FLASK APP INIT
# =============================================================================
app = Flask(__name__)
CORS(app, resources={r"/*": {"origins": "*"}}, support_credentials=True)


# =============================================================================
# ML ENGINE - Triple-Tier Trust Scoring
# =============================================================================
class IoTrustMLEngine:
    def __init__(self):
        self.lgbm = None
        self.rf = None
        self.isof = None
        self.scaler = None
        self.device_name_le = None
        self.mac_prefix_le = None

        # Tier 1: Golden Database - Verified genuine devices
        # Format: {mac_prefix: {'name': device_name, 'verified': timestamp}}
        self.golden_database = {
            # Apple
            '00:25:96': {'name': 'AirPods_Pro', 'verified': '2024-01-01'},
            '00:1F': {'name': 'Apple_Device', 'verified': '2024-01-01'},
            'A4:83': {'name': 'Apple_Device', 'verified': '2024-01-01'},
            'F0:18': {'name': 'Apple_Device', 'verified': '2024-01-01'},
            # Samsung
            '20:AB': {'name': 'Galaxy_Buds', 'verified': '2024-01-01'},
            '38:A4': {'name': 'Samsung_Wearable', 'verified': '2024-01-01'},
            # Huawei
            '78:85': {'name': 'Huawei_Watch_GT', 'verified': '2024-01-01'},
        }

        # Signal buffer for RSSI packet collection
        self.signal_buffer = {}  # {mac: [rssi1, rssi2, ...]}
        self.BUFFER_SIZE = 5

    # -------------------------------------------------------------------------
    # Model Loading
    # -------------------------------------------------------------------------
    def load_models(self, folder_path):
        self.lgbm = joblib.load(os.path.join(folder_path, 'lgbm.joblib'))
        self.rf = joblib.load(os.path.join(folder_path, 'rf.joblib'))
        self.isof = joblib.load(os.path.join(folder_path, 'isof.joblib'))
        self.scaler = joblib.load(os.path.join(folder_path, 'scaler.joblib'))
        self.device_name_le = joblib.load(os.path.join(folder_path, 'device_name_le.joblib'))
        self.mac_prefix_le = joblib.load(os.path.join(folder_path, 'mac_prefix_le.joblib'))

        # Load Golden Database from CSV if available
        golden_db_path = os.path.join(os.path.dirname(folder_path), 'Golden_Database.csv')
        try:
            if os.path.exists(golden_db_path):
                golden_df = pd.read_csv(golden_db_path)
                self.golden_database = {}
                for _, row in golden_df.iterrows():
                    self.golden_database[row['mac_prefix'].upper()] = {
                        'name': row['device_name'],
                        'verified': row.get('date_added', 'Unknown'),
                        'trust_level': row.get('trust_level', 'VERIFIED')
                    }
                print(f"[GOLDEN DB] Loaded {len(self.golden_database)} devices from CSV")
            else:
                print(f"[GOLDEN DB] CSV not found at {golden_db_path}, using default database")
        except Exception as e:
            print(f"[GOLDEN DB] Error loading CSV: {e}, using default database")

    # -------------------------------------------------------------------------
    # Feature Preprocessing
    # -------------------------------------------------------------------------
    def preprocess_telemetry(self, df, fit=False):
        df = df.copy()
        df.fillna(df.select_dtypes(include=[np.number]).mean(), inplace=True)
        if fit:
            df['device_name_encoded'] = self.device_name_le.fit_transform(df['device_name'])
            df['mac_prefix_encoded'] = self.mac_prefix_le.fit_transform(df['mac_prefix'])
        else:
            df['device_name_encoded'] = self.device_name_le.transform(df['device_name'])
            df['mac_prefix_encoded'] = self.mac_prefix_le.transform(df['mac_prefix'])
        return df

    # -------------------------------------------------------------------------
    # Trust Score Generation
    # -------------------------------------------------------------------------
    def generate_trust_score(self, row):
        """
        Universal BLE auditing engine.
        Treats all devices as "Unknown Subject" unless in Golden Database.

        Core Metrics:
        - UUID Entropy: High = Professional device
        - Service Cardinality: More services = More likely genuine
        - RSSI Jitter: Stable = Physical hardware; Volatile = Software-simulated clone
        """
        mac_prefix = row.get('mac_prefix', '').upper()
        device_name = row.get('device_name', '')

        # --- Tier 1: Golden Database Lookup (Strict MAC Verification) ---
        # A device is ONLY Tier 1 if its MAC Address EXACTLY matches Golden_Database.csv
        # Name matching is IGNORED - only MAC address matters for Tier 1 verification
        tier1_verified = False
        tier1_info = None

        if mac_prefix in self.golden_database:
            tier1_verified = True
            tier1_info = self.golden_database[mac_prefix]

        # Return immediately if found in Golden Database
        if tier1_verified:
            return {
                'trust_score': 100.0,
                'verdict': 'VERIFIED GENUINE',
                'rationale': f"Verified in Golden Database: {tier1_info['name']}",
                'lgbm_proba': 1.0,
                'rf_proba': 1.0,
                'anomaly_score': 0.0,
                'ensemble_score': 1.0,
                'tier': 1
            }

        # --- Tier 2: Universal Feature Extraction ---
        uuid_entropy = row.get('uuid_entropy', 0)
        service_count = row.get('service_count', 0)
        rssi_jitter = row.get('rssi_jitter', 0)
        adv_interval = row.get('adv_interval', 100)
        packet_loss_rate = row.get('packet_loss_rate', 0)

        # Prepare feature vector for ML models
        df_row = pd.DataFrame([row])
        df_row = self.preprocess_telemetry(df_row, fit=False)
        features = ['uuid_entropy', 'rssi_jitter', 'adv_interval', 'service_count',
                    'packet_loss_rate', 'device_name_encoded', 'mac_prefix_encoded']
        X = df_row[features]
        X_scaled = self.scaler.transform(X)
        X_df = pd.DataFrame(X_scaled, columns=features)

        # Ensemble: Average of LGBM and RF probabilities
        lgbm_proba = float(self.lgbm.predict_proba(X_df)[0][1])
        rf_proba = float(self.rf.predict_proba(X_df)[0][1])
        ensemble_score = (lgbm_proba + rf_proba) / 2.0

        # --- Tier 3: Anomaly Detection (Isolation Forest) ---
        anomaly_score_raw = float(self.isof.decision_function(X_df)[0])
        anomaly_prob = 1 / (1 + np.exp(anomaly_score_raw))

        # Base trust score from ensemble
        trust_score = ensemble_score * 100

        # --- Feature-Based Adjustments ---
        # Metric 1: UUID Entropy (Shannon Diversity Index)
        if uuid_entropy > 2.8:
            trust_score += 5  # Professional device bonus

        # Metric 2: Service Cardinality
        if service_count >= 3:
            trust_score += 10  # Genuine device bonus
        elif service_count == 0:
            trust_score -= 10  # Bare advertisement penalty

        # Metric 3: RSSI Jitter (Signal Stability)
        if rssi_jitter > 10:
            trust_score -= 15  # Software-simulated clone penalty
        elif rssi_jitter > 5:
            trust_score -= 5   # Unstable signal

        # Metric 4: Advertisement Interval Regularity
        if adv_interval > 500:
            trust_score -= 10  # Irregular interval penalty

        # Clamp to valid range
        trust_score = max(0, min(100, trust_score))

        # --- Tier 3 Override: Cap at 39% if anomaly detected ---
        tier3_anomaly_detected = False
        if anomaly_score_raw < -0.15 or anomaly_prob > 0.7:
            tier3_anomaly_detected = True
            trust_score = min(trust_score, 39.0)

        # --- Dynamic Verdict Mapping ---
        if tier3_anomaly_detected:
            verdict = 'SUSPICIOUS / ANOMALY'
        elif trust_score > 75:
            verdict = 'OPTIMIZED / GENUINE'
        elif trust_score >=     40:
            verdict = 'UNVERIFIED / NEUTRAL'
        else:
            verdict = 'SUSPICIOUS / ANOMALY'

        # --- Build Rationale String ---
        rationale_parts = []

        if tier3_anomaly_detected:
            rationale_parts.append('Tier 3 Anomaly Detected')

        if uuid_entropy > 2.8:
            rationale_parts.append('High UUID Entropy (Professional)')
        if service_count >= 3:
            rationale_parts.append('High Service Cardinality (Genuine)')
        elif service_count == 0:
            rationale_parts.append('No Services (Bare Advertisement)')
        if rssi_jitter > 10:
            rationale_parts.append('High RSSI Jitter (Simulated)')
        elif rssi_jitter > 5:
            rationale_parts.append('Unstable Signal')
        if adv_interval > 500:
            rationale_parts.append('Irregular Advertisement Interval')

        if not rationale_parts:
            rationale = 'All metrics within normal parameters'
        else:
            rationale = '; '.join(rationale_parts)

        return {
            'trust_score': float(round(trust_score, 1)),
            'verdict': str(verdict),
            'rationale': str(rationale),
            'lgbm_proba': float(round(lgbm_proba, 3)),
            'rf_proba': float(round(rf_proba, 3)),
            'anomaly_score': float(round(anomaly_prob, 3)),
            'ensemble_score': float(round(ensemble_score, 3)),
            'tier': 3 if tier3_anomaly_detected else 2
        }


# =============================================================================
# BLE SCANNER SERVICE
# =============================================================================
class BLEScannerService:
    def __init__(self):
        self.devices = {}       # Persistent device cache
        self.last_seen = {}     # Timestamp tracking per device
        self.is_scanning = False
        import time
        self.time_module = time

        # Signal buffer for RSSI packet collection
        self.signal_buffer = {}  # {mac: [rssi1, rssi2, ...]}
        self.BUFFER_SIZE = 5

        # Manufacturer data signatures for earbuds/wearables
        self.MANUFACTURER_SIGNATURES = {
            # Apple (Company ID 0x004C)
            'Apple AirPods': {'company_id': '0x004C', 'patterns': ['AirPods', 'Beats']},
            'Apple iPhone': {'company_id': '0x004C', 'patterns': ['iPhone']},
            'Apple Watch': {'company_id': '0x004C', 'patterns': ['Watch']},
            # Samsung (Company ID 0x0075)
            'Samsung Galaxy Buds': {'company_id': '0x0075', 'patterns': ['Buds', 'Galaxy']},
            'Samsung Wearable': {'company_id': '0x0075', 'patterns': ['Samsung', 'Galaxy']},
            # Huawei (Company ID 0x0175)
            'Huawei FreeBuds': {'company_id': '0x0175', 'patterns': ['FreeBuds', 'Huawei']},
            'Huawei Watch': {'company_id': '0x0175', 'patterns': ['Watch', 'Huawei', 'GT ']},
            # Sony (Company ID 0x0127)
            'Sony WF': {'company_id': '0x0127', 'patterns': ['WF-', 'WH-', 'WI-']},
            # Bose (Company ID 0x0076)
            'Bose QC': {'company_id': '0x0076', 'patterns': ['Bose', 'QuietComfort']},
            # Jabra (Company ID 0x0137)
            'Jabra Elite': {'company_id': '0x0137', 'patterns': ['Jabra', 'Elite']},
        }

    # -------------------------------------------------------------------------
    # Bluetooth Status Check
    # -------------------------------------------------------------------------
    def check_bluetooth_status(self):
        """Returns (is_available, error_message) tuple."""
        try:
            import platform
            system = platform.system()
            if system != 'Windows':
                return True, None

            # On Windows, actual check happens during scan
            return True, None

        except Exception as e:
            print(f"[BT Status] Check error: {e}")
            return True, None

    # -------------------------------------------------------------------------
    # Manufacturer Data Parsing
    # -------------------------------------------------------------------------
    def _parse_manufacturer_data(self, advertising_data):
        """Detect earbuds/wearables from manufacturer data signatures."""
        detected_brands = []

        try:
            if hasattr(advertising_data, 'manufacturer_data'):
                manufacturer_data = advertising_data.manufacturer_data
                for company_id, data in manufacturer_data.items():
                    company_hex = hex(company_id) if isinstance(company_id, int) else company_id

                    for brand, sig in self.MANUFACTURER_SIGNATURES.items():
                        if sig['company_id'].lower() == company_hex.lower():
                            detected_brands.append(brand)
                            break
        except Exception:
            pass

        return detected_brands

    # -------------------------------------------------------------------------
    # Signal Buffer Management
    # -------------------------------------------------------------------------
    def _update_signal_buffer(self, mac, rssi):
        """Append RSSI reading to buffer, keep last BUFFER_SIZE entries."""
        if mac not in self.signal_buffer:
            self.signal_buffer[mac] = []

        self.signal_buffer[mac].append(rssi)

        if len(self.signal_buffer[mac]) > self.BUFFER_SIZE:
            self.signal_buffer[mac] = self.signal_buffer[mac][-self.BUFFER_SIZE:]

    def _get_buffer_stats(self, mac):
        """Return (mean, variance) from signal buffer if enough readings."""
        if mac not in self.signal_buffer or len(self.signal_buffer[mac]) < 2:
            return None, None

        readings = self.signal_buffer[mac]
        mean_rssi = np.mean(readings)
        variance_rssi = np.var(readings)

        return mean_rssi, variance_rssi

    # -------------------------------------------------------------------------
    # Windows Native BLE Enumeration
    # -------------------------------------------------------------------------
    async def scan_windows_native(self):
        """Enumerate BLE devices via WinRT API (matches Windows Settings)."""
        try:
            from winrt.windows.devices.bluetooth import BluetoothLEDevice
            from winrt.windows.devices.enumeration import DeviceInformation

            print("[WinRT] Starting Windows native device enumeration...")

            selector = BluetoothLEDevice.GetDeviceSelector()
            devices_info = await DeviceInformation.FindAllAsync(selector)

            print(f"[WinRT] Found {len(devices_info)} devices from Windows stack")

            results = []

            for info in devices_info:
                try:
                    device_id = info.Id

                    # Extract MAC from device ID
                    if "_" in device_id:
                        mac_part = device_id.split("_")[-1]
                        mac = "-".join([mac_part[i:i+2] for i in range(0, len(mac_part), 2)])
                    else:
                        mac = device_id

                    name = info.Name if info.Name else f"Unknown ({mac})"

                    # Check connection status
                    is_connected = False
                    try:
                        ble_device = await BluetoothLEDevice.FromIdAsync(device_id)
                        if ble_device:
                            is_connected = ble_device.ConnectionStatus == "Connected"
                    except:
                        pass

                    # Default telemetry values (WinRT doesn't expose RSSI)
                    rssi = -70
                    rssi_jitter = 1.0
                    adv_interval = 100.0
                    service_count = 1
                    packet_loss_rate = 0.01

                    # Classify device type
                    if 'AirPods' in name or name.startswith('Apple') or 'iPhone' in name:
                        device_name = 'AirPods_Gen2'
                        mac_prefix = '00:25:96'
                    else:
                        device_name = 'Unknown_Sensor'
                        mac_prefix = 'FF:FF:FF'

                    results.append({
                        'mac_address': mac.upper(),
                        'local_name': name,
                        'rssi': rssi,
                        'uuid_entropy': 2.5,
                        'rssi_jitter': rssi_jitter,
                        'adv_interval': adv_interval,
                        'service_count': service_count,
                        'packet_loss_rate': packet_loss_rate,
                        'device_name': device_name,
                        'mac_prefix': mac_prefix,
                        'category': 'named' if name else 'background',
                        'is_connected': is_connected,
                        'source': 'windows_native'
                    })

                except Exception as e:
                    print(f"[WinRT] Error processing device: {e}")
                    continue

            # Sort: connected first, then by name
            results.sort(key=lambda x: (not x.get('is_connected', False), x['local_name']))

            return results

        except Exception as e:
            print(f"[WinRT] Error: {e}")
            raise Exception(f"WinRT enumeration failed: {e}")

    # -------------------------------------------------------------------------
    # Background Scanning (Continuous)
    # -------------------------------------------------------------------------
    async def start_background_scan(self):
        """Continuous BLE scanning with stale device cleanup."""

        if self.is_scanning:
            return

        self.is_scanning = True
        scanner = BleakScanner(scanning_mode="active")

        def callback(device, advertising_data):
            try:
                addr = device.address
                rssi = advertising_data.rssi
                current_time = self.time_module.time()

                # Prefer advertisement_data.local_name over device.name
                name = advertising_data.local_name
                if not name:
                    name = device.name

                if addr in self.devices:
                    existing_name = self.devices[addr].get('local_name')
                    if not name and existing_name:
                        name = existing_name

                    self.devices[addr]['rssi_readings'].append(rssi)
                    self.devices[addr]['count'] = self.devices[addr].get('count', 0) + 1
                    self.devices[addr]['service_uuids'] = list(advertising_data.service_uuids)
                else:
                    self.devices[addr] = {
                        'mac_address': addr,
                        'local_name': name,
                        'rssi_readings': [rssi],
                        'service_uuids': list(advertising_data.service_uuids),
                        'tx_power': advertising_data.tx_power if hasattr(advertising_data, 'tx_power') else None,
                        'count': 1
                    }

                self.last_seen[addr] = current_time

            except Exception as e:
                print(f"[BLE Callback] Error: {e}")

        scanner.set_detection_callback(callback)

        try:
            await scanner.start()
            while self.is_scanning:
                await asyncio.sleep(1)
                self._cleanup_stale(60)
        except Exception as e:
            print(f"[BLE] Scanner error: {e}")
        finally:
            self.is_scanning = False

    def _cleanup_stale(self, timeout=60):
        """Remove devices not seen in timeout seconds."""
        current_time = self.time_module.time()
        stale = [addr for addr, last in self.last_seen.items()
                 if current_time - last > timeout]
        for addr in stale:
            self.devices.pop(addr, None)
            self.last_seen.pop(addr, None)

    # -------------------------------------------------------------------------
    # Main Scan Entry Point
    # -------------------------------------------------------------------------
    async def scan(self, duration=20):
        # Use bleak scanner directly (WinRT API not reliably available)
        if self.is_scanning:
            return self._extract_features()

        # One-time scan fallback
        self.devices = {}

        def detection_callback(device, advertising_data):
            print(f"DEBUG: Found {device.address} - {device.name}")
            try:
                addr = device.address
                rssi = advertising_data.rssi

                # Prefer advertisement_data.local_name
                name = advertising_data.local_name
                if not name:
                    name = device.name
                if not name:
                    name = f"IoT Device ({addr})"

                # Capture ALL advertisement data - no filtering
                manufacturer_data = {}
                if hasattr(advertising_data, 'manufacturer_data'):
                    for company_id, data_bytes in advertising_data.manufacturer_data.items():
                        try:
                            if isinstance(data_bytes, bytes):
                                manufacturer_data[str(company_id)] = data_bytes.hex()
                            else:
                                manufacturer_data[str(company_id)] = str(data_bytes)
                        except Exception as e:
                            print(f"[BLE] Warning: Could not convert manufacturer data for {company_id}: {e}")
                            continue

                if addr not in self.devices:
                    self.devices[addr] = {
                        'mac_address': addr,
                        'local_name': name,
                        'rssi_readings': [rssi],
                        'service_uuids': list(advertising_data.service_uuids),
                        'tx_power': advertising_data.tx_power if hasattr(advertising_data, 'tx_power') else None,
                        'manufacturer_data': manufacturer_data,
                        'count': 1
                    }
                else:
                    self.devices[addr]['rssi_readings'].append(rssi)
                    self.devices[addr]['count'] += 1
                    self.devices[addr]['local_name'] = name
                    self.devices[addr]['service_uuids'] = list(advertising_data.service_uuids)
                    self.devices[addr]['manufacturer_data'] = manufacturer_data
            except Exception as e:
                print(f"[BLE Callback] Error: {e}")

        # Active scanning with no UUID filtering
        scanner = BleakScanner(
            detection_callback=detection_callback,
            scanning_mode="active",
            service_uuids=None
        )

        try:
            await scanner.start()
            await asyncio.sleep(duration)

        except OSError as e:
            error_msg = str(e).lower()
            if 'busy' in error_msg or ' unavailable' in error_msg:
                print("[BLE] ERROR: Bluetooth radio is busy or unavailable. Please try again.")
                raise Exception("Bluetooth Radio Busy - Please try again or check Bluetooth settings")
            else:
                print(f"[BLE] Scanner OS error: {e}")
                raise
        except Exception as e:
            print(f"[BLE] Scanner error: {e}")
            raise
        finally:
            try:
                await scanner.stop()
            except Exception as e:
                print(f"[BLE] Error stopping scanner: {e}")

        return self._extract_features()

    # -------------------------------------------------------------------------
    # Feature Extraction from Cached Devices
    # -------------------------------------------------------------------------
    def _extract_features(self):
        named_devices = []
        background_devices = []
        seen_names = {}  # Deduplication by name

        for addr, data in self.devices.items():
            rssi_readings = data['rssi_readings']
            latest_rssi = rssi_readings[-1] if rssi_readings else -100

            name = data['local_name']

            has_name = name and not name.startswith('IoT Device') and not name.startswith('Unknown (')
            is_strong = latest_rssi >= -50

            if has_name:
                display_name = name
            elif is_strong:
                display_name = addr.upper()
            else:
                continue

            # Deduplicate named devices (keep strongest RSSI)
            if has_name:
                if display_name in seen_names:
                    if latest_rssi > seen_names[display_name]['rssi']:
                        seen_names[display_name] = {'addr': addr, 'rssi': latest_rssi, 'data': data, 'display_name': display_name}
                    continue
                seen_names[display_name] = {'addr': addr, 'rssi': latest_rssi, 'data': data, 'display_name': display_name}
            else:
                background_devices.append({'addr': addr, 'rssi': latest_rssi, 'data': data, 'display_name': display_name})

        # Sort by signal strength
        sorted_named = sorted(seen_names.values(), key=lambda x: x['rssi'], reverse=True)
        background_devices = sorted(background_devices, key=lambda x: x['rssi'], reverse=True)

        results = []

        # Process named devices
        for info in sorted_named:
            data = info['data']
            rssi_readings = data['rssi_readings']
            latest_rssi = rssi_readings[-1] if rssi_readings else -100

            addr = info['addr']

            # Update signal buffer for jitter calculation
            for rssi in rssi_readings:
                self._update_signal_buffer(addr, rssi)

            buffer_mean, buffer_variance = self._get_buffer_stats(addr)

            if buffer_mean is not None:
                rssi_jitter = float(np.sqrt(buffer_variance)) if buffer_variance else 0.0
            else:
                rssi_jitter = float(np.std(rssi_readings)) if len(rssi_readings) > 1 else 0.0

            adv_interval = 100.0
            service_uuids = data['service_uuids']
            entropy = self._shannon_entropy(''.join(service_uuids)) if service_uuids else 0.0
            service_count = len(service_uuids)
            packet_loss_rate = min(0.15, rssi_jitter / 100)

            display_name = info['display_name']

            # Brand detection from name
            if 'AirPods' in display_name or display_name.startswith('Apple') or 'iPhone' in display_name:
                device_name = 'AirPods_Gen2'
                mac_prefix = '00:25:96'
            elif 'Galaxy' in display_name or 'Buds' in display_name or display_name.startswith('Samsung'):
                device_name = 'Samsung_Wearable'
                mac_prefix = '20:AB'
            elif 'FreeBuds' in display_name or 'Huawei' in display_name or 'GT ' in display_name or 'Watch' in display_name:
                device_name = 'Huawei_Wearable'
                mac_prefix = '78:85'
            else:
                device_name = 'Unknown_Sensor'
                mac_prefix = 'FF:FF:FF'

            manufacturer_detected = data.get('manufacturer_data', [])

            results.append({
                'mac_address': info['addr'],
                'local_name': display_name,
                'rssi': latest_rssi,
                'uuid_entropy': round(entropy, 2),
                'rssi_jitter': round(rssi_jitter, 2),
                'adv_interval': round(adv_interval, 2),
                'service_count': service_count,
                'packet_loss_rate': round(packet_loss_rate, 2),
                'device_name': device_name,
                'mac_prefix': mac_prefix,
                'category': 'named',
                'manufacturer_data': manufacturer_detected,
                'buffer_packets': len(self.signal_buffer.get(addr, []))
            })

        # Process background devices (limit to 10)
        for info in background_devices[:10]:
            data = info['data']
            rssi_readings = data['rssi_readings']
            latest_rssi = rssi_readings[-1] if rssi_readings else -100

            rssi_jitter = float(np.std(rssi_readings)) if len(rssi_readings) > 1 else 0.0
            adv_interval = 100.0
            service_uuids = data['service_uuids']
            entropy = self._shannon_entropy(''.join(service_uuids)) if service_uuids else 0.0
            service_count = len(service_uuids)
            packet_loss_rate = min(0.15, rssi_jitter / 100)

            results.append({
                'mac_address': info['addr'],
                'local_name': info['display_name'],
                'rssi': latest_rssi,
                'uuid_entropy': round(entropy, 2),
                'rssi_jitter': round(rssi_jitter, 2),
                'adv_interval': round(adv_interval, 2),
                'service_count': service_count,
                'packet_loss_rate': round(packet_loss_rate, 2),
                'device_name': 'Unknown_Sensor',
                'mac_prefix': 'FF:FF:FF',
                'category': 'background'
            })

        return results

    # -------------------------------------------------------------------------
    # Shannon Entropy Calculation
    # -------------------------------------------------------------------------
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


# =============================================================================
# INITIALIZE SERVICES
# =============================================================================
engine = IoTrustMLEngine()
engine.load_models('saved_models')
print("SUCCESS: All 3 models loaded from saved_models/")

ble_scanner = BLEScannerService()
ble_scan_results = []


# =============================================================================
# API ROUTES
# =============================================================================
@app.route('/scan_nearby', methods=['GET'])
def scan_nearby():
    print("[SCAN] Getting device list...")
    try:
        devices = asyncio.run(ble_scanner.scan(duration=20))
        global ble_scan_results

        if devices is None:
            devices = []

        ble_scan_results = devices
        print(f"[SCAN] Found {len(devices)} devices")

        if len(devices) == 0:
            return jsonify([])

        return jsonify(devices)
    except Exception as e:
        print(f"[SCAN] Error: {e}")
        error_msg = str(e)

        if 'powered off' in error_msg.lower() or 'powered_off' in error_msg.lower():
            return jsonify({'error': 'Bluetooth is turned off. Please enable Bluetooth in Windows Settings.'}), 200
        elif 'Permission' in error_msg or 'Access' in error_msg:
            return jsonify({'error': 'Bluetooth permission denied. Try running as administrator or check Windows Bluetooth permissions.'}), 200
        elif 'not found' in error_msg.lower() or 'adapter' in error_msg.lower():
            return jsonify({'error': 'Bluetooth Adapter not found. Please ensure Bluetooth is enabled on your device.'}), 200
        elif 'Timeout' in error_msg:
            return jsonify({'error': 'Bluetooth scan timed out. Please try again.'}), 200
        else:
            return jsonify({'error': f'BLE scan failed: {error_msg}'}), 200


@app.route('/start_background_scan', methods=['POST'])
def start_background_scan():
    print("[SCAN] Starting background scan...")
    try:
        if not ble_scanner.is_scanning:
            asyncio.create_task(ble_scanner.start_background_scan())
            return jsonify({'status': 'Background scanning started'})
        else:
            return jsonify({'status': 'Already scanning'})
    except Exception as e:
        print(f"[SCAN] Error: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/audit', methods=['POST'])
def audit():
    print(f"[AUDIT] Received request from {request.remote_addr}")
    data = request.get_json() or {}
    print(f"[AUDIT] Input data: {data}")

    # Safe defaults for missing attributes
    DEFAULT_VALUES = {
        'device_name': 'Unknown_Sensor',
        'mac_prefix': 'FF:FF:FF',
        'uuid_entropy': 2.5,
        'rssi_jitter': 0.5,
        'adv_interval': 100.0,
        'service_count': 3,
        'packet_loss_rate': 0.0,
        'rssi': -70
    }

    for key, default in DEFAULT_VALUES.items():
        if key not in data or data.get(key) is None:
            data[key] = default

    # Ensure device_name and mac_prefix are known labels
    known_device_names = list(engine.device_name_le.classes_)
    known_mac_prefixes = list(engine.mac_prefix_le.classes_)

    if data.get('device_name') not in known_device_names:
        data['device_name'] = 'Mixed_Device'
    if data.get('mac_prefix') not in known_mac_prefixes:
        data['mac_prefix'] = 'FF:FF:FF'

    try:
        result = engine.generate_trust_score(data)
        print(f"[AUDIT] Result: {result}")

        # Convert numpy types to native Python for JSON serialization
        def convert_to_native(obj):
            if isinstance(obj, bytes):
                return obj.hex()
            if hasattr(obj, 'item'):
                return obj.item()
            elif hasattr(obj, 'tolist'):
                return obj.tolist()
            elif isinstance(obj, dict):
                return {k: convert_to_native(v) for k, v in obj.items()}
            elif isinstance(obj, list):
                return [convert_to_native(i) for i in obj]
            return obj

        result = convert_to_native(result)

        return jsonify(result)
    except Exception as e:
        print(f"[AUDIT] Error: {e}")
        return jsonify({'error': f'Audit failed: {str(e)}'}), 200


@app.route('/add_to_golden_database', methods=['POST'])
def add_to_golden_database():
    """Add a device to the Tier 1 whitelist."""
    data = request.get_json() or {}

    mac_prefix = data.get('mac_prefix', '').upper()
    device_name = data.get('device_name', 'Unknown')
    local_name = data.get('local_name', '')

    if not mac_prefix:
        return jsonify({'error': 'MAC prefix is required'}), 200

    from datetime import datetime
    engine.golden_database[mac_prefix] = {
        'name': device_name,
        'verified': datetime.now().strftime('%Y-%m-%d'),
        'local_name': local_name
    }

    print(f"[GOLDEN DB] Added: {mac_prefix} - {device_name}")

    return jsonify({
        'success': True,
        'message': f'Device {device_name} added to Golden Database',
        'mac_prefix': mac_prefix,
        'device_name': device_name
    })


@app.route('/get_golden_database', methods=['GET'])
def get_golden_database():
    """Return all devices in the Golden Database."""
    return jsonify(engine.golden_database)


@app.route('/health', methods=['GET'])
def health():
    return jsonify({'status': 'ok'})


# =============================================================================
# MAIN ENTRY POINT
# =============================================================================
if __name__ == '__main__':
    # threaded=True prevents freezing when Bluetooth hardware is busy
    app.run(debug=True, host='127.0.0.1', port=5000, threaded=True)
