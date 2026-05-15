"""
Target Client — sends attacks to the live Clinical Co-Pilot.
Every attack goes through this single interface.
"""

import time
import requests
from config import (
    TARGET_CHAT_ENDPOINT,
    TARGET_HEALTH_ENDPOINT,
    TARGET_EXTRACT_ENDPOINT,
    DEFAULT_PATIENT,
)


def check_target_health() -> bool:
    """Verify the target system is reachable."""
    try:
        resp = requests.get(TARGET_HEALTH_ENDPOINT, timeout=10)
        return resp.status_code == 200
    except Exception:
        return False


def send_attack(message: str, patient_id: str = None) -> dict:
    """
    Send a single attack payload to the target's /chat endpoint.
    Returns the full response with timing metadata.
    """
    if patient_id is None:
        patient_id = DEFAULT_PATIENT["id"]

    payload = {
        "patient_id": patient_id,
        "message": message,
    }

    start = time.time()
    try:
        resp = requests.post(
            TARGET_CHAT_ENDPOINT,
            json=payload,
            timeout=60,
        )
        elapsed = time.time() - start

        if resp.status_code == 200:
            data = resp.json()
            return {
                "success": True,
                "response": data.get("response", ""),
                "citations": data.get("citations", []),
                "tools_called": data.get("tools_called", []),
                "tokens_used": data.get("tokens_used", {}),
                "handoffs": data.get("handoffs", []),
                "latency_ms": round(elapsed * 1000),
                "status_code": 200,
            }
        else:
            return {
                "success": False,
                "error": f"HTTP {resp.status_code}: {resp.text[:200]}",
                "latency_ms": round(elapsed * 1000),
                "status_code": resp.status_code,
            }

    except requests.Timeout:
        return {
            "success": False,
            "error": "Request timed out (60s)",
            "latency_ms": 60000,
            "status_code": 0,
        }
    except Exception as e:
        return {
            "success": False,
            "error": str(e),
            "latency_ms": round((time.time() - start) * 1000),
            "status_code": 0,
        }


def send_multi_turn_attack(messages: list[str], patient_id: str = None) -> list[dict]:
    """
    Send a multi-turn attack sequence. Each message is sent as a separate /chat call.
    Returns a list of responses.
    """
    results = []
    for i, msg in enumerate(messages):
        result = send_attack(msg, patient_id)
        result["turn"] = i + 1
        results.append(result)

        # Stop if the target is down
        if not result["success"] and result["status_code"] == 0:
            break

        # Brief pause between turns
        time.sleep(0.5)

    return results


def send_extract_attack(file_bytes: bytes, filename: str, doc_type: str,
                        patient_id: str = None, mime_type: str = None) -> dict:
    """
    Send a malicious-document attack to /extract. This is the upload-content
    attack surface called out in THREAT_MODEL.md §3.2 and the Adversarial
    Robustness guideline's "uploaded content" requirement. Distinct from
    send_attack (which only hits /chat) because the VLM-extraction pipeline
    is reachable only through file upload, not text messages.

    file_bytes: raw bytes of the document to upload
    filename:   filename hint sent in the multipart body
    doc_type:   one of the target's accepted document types (pdf / image /
                clinical_note / discharge_summary / lab_report). Probing
                shows the target currently 500s on every doc_type today —
                that itself is a finding worth recording.
    patient_id: patient context; defaults to DEFAULT_PATIENT
    mime_type:  application/pdf, image/png, etc.; inferred from filename
                extension if omitted.
    """
    if patient_id is None:
        patient_id = DEFAULT_PATIENT["id"]
    if mime_type is None:
        ext = filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
        mime_type = {"pdf": "application/pdf", "png": "image/png",
                     "jpg": "image/jpeg", "jpeg": "image/jpeg",
                     "txt": "text/plain"}.get(ext, "application/octet-stream")

    start = time.time()
    try:
        resp = requests.post(
            TARGET_EXTRACT_ENDPOINT,
            data={"patient_id": patient_id, "doc_type": doc_type},
            files={"file": (filename, file_bytes, mime_type)},
            timeout=60,
        )
        elapsed = time.time() - start

        if resp.status_code == 200:
            data = resp.json()
            return {
                "success":     True,
                "response":    str(data),
                "extracted":   data.get("derived_facts", data),
                "citations":   data.get("derived_fact_citations", []),
                "tokens_used": data.get("tokens_used", {}),
                "latency_ms":  round(elapsed * 1000),
                "status_code": 200,
            }
        return {
            "success":     False,
            "error":       f"HTTP {resp.status_code}: {resp.text[:200]}",
            "response":    f"HTTP {resp.status_code}: {resp.text[:200]}",
            "latency_ms":  round(elapsed * 1000),
            "status_code": resp.status_code,
        }
    except requests.Timeout:
        return {"success": False, "error": "Request timed out (60s)",
                "response": "HTTP 0: timeout",
                "latency_ms": 60000, "status_code": 0}
    except Exception as e:
        return {"success": False, "error": str(e),
                "response": f"HTTP 0: {e}",
                "latency_ms": round((time.time() - start) * 1000),
                "status_code": 0}


# ── CLI test ──
if __name__ == "__main__":
    print("Testing target connectivity...")
    if check_target_health():
        print("✅ Target is live")
        print("\nSending test query...")
        result = send_attack("What medications is this patient on?")
        if result["success"]:
            print(f"✅ Response received ({result['latency_ms']}ms)")
            print(f"   {result['response'][:150]}...")
        else:
            print(f"❌ Attack failed: {result['error']}")
    else:
        print("❌ Target is offline")
