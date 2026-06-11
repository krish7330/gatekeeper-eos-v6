#!/usr/bin/env python3
"""
Oracle v0.1 — Red text extractor for Oracle 1Z0-082 PDF.

Extracts spans of red-colored text from a PDF and writes them
to red_answers.json in a binary schema.

Gatekeeper integration: before reading, Oracle requests policy evaluation.
ALLOW → proceed. BLOCK → abort.

Usage:
    python oracle_v0.1.py <path_to_pdf>
"""

import sys
import json
import fitz  # PyMuPDF

# Gatekeeper integration
from src.gatekeeper_eos_v6.policy import GatekeeperPolicy

# Default policy (config-driven from policy.json)
_gatekeeper = GatekeeperPolicy()

# Red color thresholds
# PyMuPDF stores color as packed integer 0xRRGGBB (0–255 per channel)
R_MIN = 180   # red channel minimum (0–255)
G_MAX = 100   # green channel maximum (0–255)
B_MAX = 100   # blue channel maximum (0–255)


def _unpack_color(color) -> tuple:  # (r, g, b) in 0-255
    """Convert PyMuPDF color (int or tuple) to (r, g, b) 0–255."""
    if color is None:
        return None
    if isinstance(color, int):
        # Packed integer 0xRRGGBB
        return ((color >> 16) & 0xFF, (color >> 8) & 0xFF, color & 0xFF)
    if isinstance(color, (list, tuple)) and len(color) >= 3:
        r, g, b = color[0], color[1], color[2]
        if max(r, g, b) <= 1.0:
            return (int(r * 255), int(g * 255), int(b * 255))
        return (int(r), int(g), int(b))
    return None


def is_red(color) -> bool:
    """Check if a color qualifies as 'red' using RGB thresholds."""
    rgb = _unpack_color(color)
    if rgb is None:
        return False
    r, g, b = rgb
    return r >= R_MIN and g <= G_MAX and b <= B_MAX


def extract_red_spans(pdf_path: str) -> list[dict]:
    """
    Extract all red-colored text spans from the PDF.

    Returns a list of dicts with:
      - page: int (1-based)
      - text: str
      - color: [r, g, b]
      - bbox: [x0, y0, x1, y1]
    """
    red_spans = []
    doc = fitz.open(pdf_path)

    for page_num, page in enumerate(doc, start=1):
        blocks = page.get_text("dict", flags=fitz.TEXT_PRESERVE_WHITESPACE)["blocks"]
        for block in blocks:
            if block["type"] != 0:  # skip images
                continue
            for line in block.get("lines", []):
                for span in line.get("spans", []):
                    color = span.get("color")
                    text = span.get("text", "").strip()
                    if text and is_red(color):
                        rgb = _unpack_color(color)
                        red_spans.append({
                            "page": page_num,
                            "text": text,
                            "color": list(rgb) if rgb else None,
                            "bbox": list(span.get("bbox", [])),
                        })

    doc.close()
    return red_spans


def main(policy: GatekeeperPolicy | None = None):
    if len(sys.argv) < 2 and policy is None:
        print("Usage: python oracle_v0.1.py <path_to_pdf>", file=sys.stderr)
        sys.exit(1)

    pdf_path = sys.argv[1] if len(sys.argv) >= 2 else ""

    # Gatekeeper gate: evaluate before reading
    gate = policy or _gatekeeper
    decision = gate.evaluate_action({"tool": "read_file", "target": pdf_path})
    if decision["status"] == "BLOCK":
        print(f"Gatekeeper: BLOCKED — {decision.get('reason', 'Not authorized.')}", file=sys.stderr)
        sys.exit(3)

    print(f"Gatekeeper: ALLOW — {decision.get('reason', '')}")
    print(f"Extracting red spans from: {pdf_path}")

    spans = extract_red_spans(pdf_path)
    print(f"Found {len(spans)} red text span(s)")

    # Binary schema: top-level meta + data array
    output = {
        "version": "0.1",
        "source": pdf_path,
        "total_spans": len(spans),
        "spans": spans,
    }

    with open("red_answers.json", "w") as f:
        json.dump(output, f, indent=2)

    print("Wrote red_answers.json")

    if spans:
        print(f"\nFirst red span (page {spans[0]['page']}): {spans[0]['text']}")
    else:
        print("\nWARNING: No red spans found.")
        print("Debug: uncomment the debug block below and rerun to see actual colors.")
        # Debug: uncomment to see all span colors
        # doc = fitz.open(pdf_path)
        # for page_num, page in enumerate(doc, start=1):
        #     blocks = page.get_text("dict", flags=fitz.TEXT_PRESERVE_WHITESPACE)["blocks"]
        #     for block in blocks:
        #         if block["type"] != 0: continue
        #         for line in block.get("lines", []):
        #             for span in line.get("spans", []):
        #                 c = span.get("color")
        #                 t = span.get("text", "").strip()
        #                 if t:
        #                     print(f"  page={page_num} color={c} text={t!r}")
        # doc.close()
        sys.exit(2)


if __name__ == "__main__":
    main()
