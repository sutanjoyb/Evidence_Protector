"""
Chain of Custody Module — Evidence Protector Pro
Hash chaining and session manifest validation for forensic integrity.
"""

import hashlib
import json
from datetime import datetime
from typing import List, Dict, Tuple

GENESIS_HASH = "GENESIS"


def sha256_hex(data: bytes) -> str:
    """Compute SHA-256 hash and return hex string."""
    return hashlib.sha256(data).hexdigest()


def canonicalize(obj) -> str:
    """
    Canonicalize JSON for reproducible hashing.
    Sorts keys, removes whitespace, consistent ordering.
    """
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
        default=str
    )


def compute_chain_hash(
    file_hash: str,
    findings_hash: str,
    previous_hash: str,
    session_id: str,
    timestamp: str
) -> str:
    """Compute the chain hash linking this session to the previous one."""
    payload = f"{file_hash}|{findings_hash}|{previous_hash}|{session_id}|{timestamp}"
    return sha256_hex(payload.encode("utf-8"))


def verify_chain_manifest(manifest: List[Dict]) -> Tuple[bool, int]:
    """
    Verify the integrity of a chain manifest.
    Returns: (is_intact, broken_index)
    - is_intact: True if all entries are valid and properly linked
    - broken_index: Index of first broken entry, or -1 if intact
    """
    if not manifest:
        return (True, -1)

    for i, entry in enumerate(manifest):
        # Verify this entry links to the previous one
        expected_prev = GENESIS_HASH if i == 0 else manifest[i - 1].get("chain_hash")
        actual_prev = entry.get("previous_session_hash")
        
        if actual_prev != expected_prev:
            return (False, i)

        # Recompute the chain hash for this entry
        computed = compute_chain_hash(
            file_hash=entry.get("file_hash", ""),
            findings_hash=entry.get("findings_hash", ""),
            previous_hash=expected_prev,
            session_id=entry.get("session_id", ""),
            timestamp=entry.get("timestamp", "")
        )

        stored = entry.get("chain_hash", "")
        if computed != stored:
            return (False, i)

    return (True, -1)


def format_chain_for_export(manifest: List[Dict], findings: Dict) -> Dict:
    """
    Format chain manifest and findings for export.
    Includes integrity verification status and timestamps.
    """
    is_intact, broken_idx = verify_chain_manifest(manifest)
    
    return {
        "chain_integrity": {
            "intact": is_intact,
            "broken_at_index": broken_idx if not is_intact else None,
            "total_sessions": len(manifest),
            "verified_at": datetime.utcnow().isoformat()
        },
        "manifest_entries": manifest,
        "findings_summary": {
            "integrity_score": findings.get("integrity_score"),
            "total_gaps": findings.get("total_gaps"),
            "incident_count": len(findings.get("incidents", []))
        }
    }


def create_chain_summary(manifest: List[Dict]) -> str:
    """
    Create a human-readable summary of the chain.
    Useful for PDF/text exports.
    """
    if not manifest:
        return "No chain entries recorded."

    lines = [
        "═" * 80,
        "CHAIN OF CUSTODY MANIFEST — Evidence Protector Pro",
        "═" * 80,
        ""
    ]

    for i, entry in enumerate(manifest, start=1):
        lines.append(f"Session #{i}")
        lines.append(f"  ID:                  {entry.get('session_id')}")
        lines.append(f"  Timestamp:           {entry.get('timestamp')}")
        lines.append(f"  File Hash:           {entry.get('file_hash', '')[:20]}...")
        lines.append(f"  Findings Hash:       {entry.get('findings_hash', '')[:20]}...")
        lines.append(f"  Previous Chain:      {entry.get('previous_session_hash', '')[:20]}...")
        lines.append(f"  Chain Hash:          {entry.get('chain_hash', '')[:20]}...")
        lines.append("")

    # Verification status
    is_intact, broken_idx = verify_chain_manifest(manifest)
    lines.append("─" * 80)
    if is_intact:
        lines.append("✓ CHAIN INTEGRITY VERIFIED: All sessions properly linked and unchanged.")
    else:
        lines.append(f"✗ CHAIN BROKEN: Mismatch detected at entry #{broken_idx + 1}")
    lines.append("═" * 80)

    return "\n".join(lines)
