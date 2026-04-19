import re
from datetime import datetime

# Improved Pattern: Handles 2026-04-11, 2026/04/11, 2026.04.11 
# and separators like 'T' or space.
TIMESTAMP_PATTERN = r'(\d{4}[-/.]\d{2}[-/.]\d{2}[T ]\d{2}:\d{2}:\d{2})'

def parse_any_date(date_str):
    """Attempts to parse different date formats found in logs."""
    formats = [
        '%Y-%m-%dT%H:%M:%S', # ISO format
        '%Y-%m-%d %H:%M:%S', # Standard format
        '%Y/%m/%d %H:%M:%S', # Alternate slashes
        '%Y.%m.%d %H:%M:%S'  # Dot separators
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str[:19], fmt)
        except ValueError:
            continue
    return None


def analyze_logs(file_path, threshold_seconds=60, use_24_hour=True):
    """
    Analyzes log file for temporal gaps and categorizes anomalies.
    Allows toggling between 12-hour and 24-hour time formats.
    """

    #  STEP 1: Decide time format based on toggle
    if use_24_hour:
        time_format = '%Y-%m-%d %H:%M:%S'
    else:
        time_format = '%Y-%m-%d %I:%M:%S %p'

    incidents = []
    last_time = None

    # Ensure threshold is an integer
    try:
        threshold_seconds = int(threshold_seconds)
    except (ValueError, TypeError):
        threshold_seconds = 60

    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
        for line in f:
            match = re.search(TIMESTAMP_PATTERN, line)
            if match:
                current_time = parse_any_date(match.group(1))

                if current_time and last_time:
                    gap = (current_time - last_time).total_seconds()

                    if gap > threshold_seconds:
                        # --- DYNAMIC ANOMALY CATEGORIZATION ---
                        if gap > 3600:
                            reason = "Extended System Blackout / High Risk Log Erasure"
                            severity = "CRITICAL"
                        elif gap > 600:
                            reason = "Significant Data Void / Potential Tampering"
                            severity = "CRITICAL"
                        elif gap > 300:
                            reason = "Service Interruption Detected"
                            severity = "WARNING"
                        else:
                            reason = "Minor Sequential Lag"
                            severity = "WARNING"

                        # STEP 2: Use dynamic format
                        incidents.append({
                            "start": last_time.strftime(time_format),
                            "end": current_time.strftime(time_format),
                            "duration": int(gap),
                            "severity": severity,
                            "details": reason
                        })

                if current_time:
                    last_time = current_time

    # Calculate Integrity Score
    score = max(0, 100.00 - (len(incidents) * 5.0))

    return {
        "total_gaps": len(incidents),
        "integrity_score": round(score, 2),
        "incidents": incidents
    }