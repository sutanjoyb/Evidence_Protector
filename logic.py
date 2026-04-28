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


def analyze_logs(file_path, threshold_seconds=60, use_24_hour=True,progress_callback=None):
    """
    Analyzes log file for temporal gaps and categorizes anomalies.
    Allows toggling between 12-hour and 24-hour time formats.
    """

    #  STEP 1: Decide time format based on toggle
    if progress_callback:
        progress_callback(10,"step1:deciding time format..")
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
                        if progress_callback:
                           progress_callback(60, "step 2 :detecting gaps in logs..")
                        incidents.append({
                            "start": last_time.strftime(time_format),
                            "end": current_time.strftime(time_format),
                            "duration": int(gap),
                            "severity": severity,
                            "details": reason
                        })

                if current_time:
                    last_time = current_time
                if progress_callback:
                   progress_callback(80,"step 3 : calculating intergrity score..")
                score = calculate_integrity_score(incidents)
    if progress_callback:
        progress_callback(100,"Analysis completed.")
    return {
        "total_gaps": len(incidents),
        "integrity_score": round(score, 2),
        "incidents": incidents
    }


def calculate_integrity_score(incidents):
    """
    Weighted integrity scoring model.

    Replaces the naive `100 - (gap_count * 5)` formula with a hybrid metric
    that accounts for:
      - Total missing time (penalises long blackouts)
      - Longest single gap (catches single catastrophic voids)
      - Gap frequency relative to log span (distribution awareness)
      - Severity-tiered per-gap penalties (threshold-based)

    Score is clamped to [0, 100].
    """
    if not incidents:
        return 100.0

    durations = [inc["duration"] for inc in incidents]
    gap_count = len(durations)
    total_gap_time = sum(durations)       # seconds
    longest_gap = max(durations)
    avg_gap = total_gap_time / gap_count

    # ── 1. FREQUENCY PENALTY (replaces flat -5 per gap) ─────────────────────
    # Short gaps hurt less; many gaps still accumulate pressure.
    # Penalty per gap scales with average gap size.
    if avg_gap < 120:           # < 2 min  → minor
        per_gap_penalty = 1.0
    elif avg_gap < 600:         # < 10 min → moderate
        per_gap_penalty = 3.0
    elif avg_gap < 3600:        # < 1 hr   → significant
        per_gap_penalty = 6.0
    else:                       # ≥ 1 hr   → critical
        per_gap_penalty = 10.0

    frequency_penalty = min(40.0, gap_count * per_gap_penalty)

    # ── 2. TOTAL DURATION PENALTY ────────────────────────────────────────────
    # Every hour of missing data costs ~10 points, capped at 35.
    hours_missing = total_gap_time / 3600
    duration_penalty = min(35.0, hours_missing * 10.0)

    # ── 3. LONGEST GAP PENALTY ───────────────────────────────────────────────
    # A single massive void is a strong tampering signal.
    if longest_gap >= 86400:        # ≥ 24 hrs
        longest_penalty = 25.0
    elif longest_gap >= 3600:       # ≥ 1 hr
        longest_penalty = 15.0
    elif longest_gap >= 600:        # ≥ 10 min
        longest_penalty = 8.0
    elif longest_gap >= 300:        # ≥ 5 min
        longest_penalty = 4.0
    else:
        longest_penalty = 1.0

    # ── 4. CLUSTERING PENALTY ────────────────────────────────────────────────
    # Many gaps in a short span suggests systematic deletion.
    # Proxy: if gap_count > 10 and avg_gap < 5 min, add extra pressure.
    clustering_penalty = 0.0
    if gap_count > 10 and avg_gap < 300:
        clustering_penalty = min(10.0, (gap_count - 10) * 0.5)

    total_penalty = frequency_penalty + duration_penalty + longest_penalty + clustering_penalty
    score = max(0.0, 100.0 - total_penalty)
    return round(score, 2)