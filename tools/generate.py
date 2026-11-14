"""Generate certificates for one event and publish them to the portal.

Usage:
    python tools/generate.py private/<event-folder>            # preview: plain PDFs + codes only
    python tools/generate.py private/<event-folder> --publish  # also write encrypted certs/ and data/<PREFIX>.json

The event folder holds:
    event.json        event details, certificate text and layout (see tools/example/event.json)
    participants.csv  (or .xlsx) one row per person; columns: name (required), id, usn, roll,
                      team, college, semester, email
It receives:
    codes.csv         the code issued to each participant; kept so re-runs reuse the same codes
    pdf/              plain (unencrypted) PDFs for checking and for sending to participants

Everything in private/ is git-ignored: it holds personal data and the codes.
The encryption matches index.html and download.html, so verification works unchanged.
"""

import argparse
import csv
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import sys
from base64 import b64encode
from xml.sax.saxutils import escape
from pathlib import Path

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from reportlab.graphics import renderPDF
from reportlab.graphics.barcode.qr import QrCodeWidget
from reportlab.graphics.shapes import Drawing
from reportlab.lib.colors import HexColor
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4, landscape
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import mm
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab import rl_config

rl_config.useA85 = 0  # store images as raw binary, not ASCII85 text (25% smaller PDFs)
from reportlab.platypus import Paragraph

ROOT = Path(__file__).resolve().parent.parent
DATA = ROOT / "data"  # one <PREFIX>.json per event
ISSUER = "AMBIT-IRISE Foundation, AMBIT Belagavi"
CERTS = ROOT / "certs"
VERIFY_URL = "https://ambit-irise.github.io/certificate/?id={code}"
ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"  # no O/0 or I/1, as download.html promises
FIELDS = ["name", "usn", "roll", "team", "college", "semester"]

# ---------------------------------------------------------------- crypto (mirrors the portal JS)

def sha(s: str) -> bytes:
    return hashlib.sha256(s.encode("utf-8")).digest()

def seal(key: bytes, data: bytes) -> tuple[bytes, bytes]:
    """AES-GCM with an IV derived from the content, so identical input gives identical output
    (re-running the generator leaves unchanged certificates byte-for-byte the same in git)."""
    iv = hmac.new(key, data, hashlib.sha256).digest()[:12]
    return iv, AESGCM(key).encrypt(iv, data, None)

def lookup_of(code): return sha("lookup:" + code).hex()
def file_of(code): return sha("file:" + code).hex()[:40] + ".bin"

def fingerprint(code, d):
    canon = "|".join([code, d["name"], d["usn"], d["team"], d["college"], d["type"],
                      d["event"], d["date"], d["semester"], d["roll"]])
    if d.get("extra"):  # event-specific fields; records without them keep the original fingerprint
        canon += "|" + "|".join(f"{label}={value}" for label, value in d["extra"])
    h = sha(canon).hex().upper()[:16]
    return "-".join(h[i:i + 4] for i in range(0, 16, 4))

# ---------------------------------------------------------------- inputs

def read_participants(folder: Path, extras=()):
    csv_path, xlsx_path = folder / "participants.csv", folder / "participants.xlsx"
    if csv_path.exists():
        with open(csv_path, newline="", encoding="utf-8-sig") as f:
            rows = list(csv.DictReader(f))
    elif xlsx_path.exists():
        from openpyxl import load_workbook
        ws = load_workbook(xlsx_path, read_only=True, data_only=True).active
        it = ws.iter_rows(values_only=True)
        head = [str(h or "").strip() for h in next(it)]
        rows = [dict(zip(head, r)) for r in it if any(c not in (None, "") for c in r)]
    else:
        sys.exit(f"No participants.csv or participants.xlsx in {folder}")
    out = []
    for i, r in enumerate(rows, start=2):
        r = {str(k).strip().lower(): ("" if v is None else str(v).strip()) for k, v in r.items() if k}
        if not r.get("name"):
            print(f"  skipped row {i}: no name")
            continue
        keys = [x["key"] for x in extras]
        p = {k: r.get(k, "") for k in FIELDS + ["id", "email"] + keys}
        for x in extras:
            v = p[x["key"]]
            if x.get("ordinal") and re.fullmatch(r"\d+(\.0)?", v):  # "1" (or 1.0 from Excel) -> "1st"
                n = int(float(v))
                v = f"{n}{'th' if 10 <= n % 100 <= 20 else {1: 'st', 2: 'nd', 3: 'rd'}.get(n % 10, 'th')}"
            p[x["key"]] = v or x.get("default", "")  # e.g. finishers without a podium place
        missing = [k for k in keys if not p[k]]
        if missing:
            print(f"  warning: row {i} ({p['name']}) has no {', '.join(missing)}")
        for x in extras:  # a field with fixed values: map what the sheet says onto the official wording
            if x.get("choices") and p[x["key"]]:
                hits = [ch["label"] for ch in x["choices"]
                        if all(re.search(m, p[x["key"]], re.I) for m in ch["match"])]
                if len(hits) != 1:
                    sys.exit(f"Row {i} ({p['name']}): {x['key']} '{p[x['key']]}' is not one of: "
                             + "; ".join(ch["label"] for ch in x["choices"]))
                p[x["key"]] = hits[0]
        p["key"] = (p["id"] or p["usn"] or p["email"] or p["roll"] or p["name"]).upper()
        out.append(p)
    keys = [p["key"] for p in out]
    dupes = {k for k in keys if keys.count(k) > 1}
    if dupes:
        sys.exit(f"Two rows share the same id/USN/email/name: {', '.join(sorted(dupes))}. "
                 "Add an 'id' column to tell them apart.")
    return out

def load_codes(path: Path):
    if not path.exists():
        return {}
    with open(path, newline="", encoding="utf-8") as f:
        return {r["key"]: r for r in csv.DictReader(f)}

def new_code(prefix, taken):
    while True:
        tail = "".join(secrets.choice(ALPHABET) for _ in range(8))
        code = f"{prefix}-{tail[:4]}-{tail[4:]}"
        if code not in taken:
            return code

# ---------------------------------------------------------------- drawing

def fill(text, ctx):
    try:
        return text.format(**ctx)
    except KeyError as e:
        sys.exit(f"event.json uses {{{e.args[0]}}}, which is not a known field")

def draw_qr(c, value, x, y, size):
    w = QrCodeWidget(value, barLevel="M")
    x0, y0, x1, y1 = w.getBounds()
    d = Drawing(size, size, transform=[size / (x1 - x0), 0, 0, size / (y1 - y0), 0, 0])
    d.add(w)
    renderPDF.draw(d, c, x, y)

def basic_template(c, W, H, ev, ctx, code):
    """A plain A4-landscape design. Replace with a background (see event.json 'template') later."""
    navy, accent, muted = HexColor("#1B1446"), HexColor(ev.get("accent", "#D6246E")), HexColor("#5d5a70")
    # border
    c.setStrokeColor(navy); c.setLineWidth(3); c.rect(10 * mm, 10 * mm, W - 20 * mm, H - 20 * mm)
    c.setStrokeColor(accent); c.setLineWidth(1); c.rect(13 * mm, 13 * mm, W - 26 * mm, H - 26 * mm)
    # logos
    logos = [ROOT / p for p in ev.get("logos", [])]
    if logos:
        box = 20 * mm
        left, right = 24 * mm, W - 24 * mm - box  # x of the first and last logo boxes
        step = (right - left) / (len(logos) - 1) if len(logos) > 1 else 0
        for i, p in enumerate(logos):
            x = left + i * step if len(logos) > 1 else (W - box) / 2
            c.drawImage(str(p), x, H - 40 * mm, box, box, preserveAspectRatio=True, mask="auto")
    # header
    # each line: (text, font, size, colour, space above its baseline in points)
    y = H - 44 * mm
    for line, font, size, color, gap in [
        (ev.get("header_small", ""), "Helvetica-Bold", 9, accent, 12),
        (ev.get("header", ""), "Times-Bold", 18, navy, 22),
        (ev.get("header_sub", ""), "Helvetica", 10, muted, 16),
    ]:
        if line:
            y -= gap
            c.setFont(font, size); c.setFillColor(color); c.drawCentredString(W / 2, y, fill(line, ctx))
    # title
    y -= 44
    c.setFont("Times-Bold", 30); c.setFillColor(navy); c.drawCentredString(W / 2, y, ctx["type"].upper())
    y -= 30
    c.setFont("Times-Italic", 14); c.setFillColor(muted); c.drawCentredString(W / 2, y, "This is to certify that")
    # name
    y -= 44
    size = 32
    while c.stringWidth(ctx["name"], "Times-Bold", size) > W - 110 * mm and size > 18:
        size -= 1
    c.setFont("Times-Bold", size); c.setFillColor(accent); c.drawCentredString(W / 2, y, ctx["name"])
    c.setStrokeColor(muted); c.setLineWidth(0.5); c.line(W / 2 - 95 * mm, y - 8, W / 2 + 95 * mm, y - 8)
    y -= 24
    team = ctx["team"]
    if team and not team.lower().startswith("team"):
        team = "Team " + team
    details = "  ·  ".join(x for x in [ctx["usn"] or ctx["roll"], team, ctx["college"]] if x)
    if details:
        c.setFont("Helvetica", 10.5); c.setFillColor(muted); c.drawCentredString(W / 2, y, details)
    y -= 16
    # body paragraph
    style = ParagraphStyle("b", fontName="Times-Roman", fontSize=15, leading=23, alignment=TA_CENTER, textColor=navy)
    safe = {k: escape(str(v)) for k, v in ctx.items()}
    para = Paragraph(fill(ev["body"], safe), style)
    pw = W - 70 * mm
    _, ph = para.wrap(pw, 60 * mm)
    para.drawOn(c, (W - pw) / 2, y - ph)
    # signatures
    sigs = ev.get("signatories", [])
    if sigs:
        slot = (W - 80 * mm) / len(sigs)
        for i, s in enumerate(sigs):
            cx = 40 * mm + slot * (i + 0.5) - (12 * mm if i == len(sigs) - 1 else 0)
            if s.get("image"):
                c.drawImage(str(ROOT / s["image"]), cx - 22 * mm, 38 * mm, 44 * mm, 14 * mm,
                            preserveAspectRatio=True, mask="auto")
            c.setStrokeColor(navy); c.line(cx - 28 * mm, 36 * mm, cx + 28 * mm, 36 * mm)
            c.setFillColor(navy); c.setFont("Helvetica-Bold", 10.5); c.drawCentredString(cx, 31 * mm, s.get("name", ""))
            c.setFillColor(muted); c.setFont("Helvetica", 9); c.drawCentredString(cx, 26.5 * mm, s.get("title", ""))
    # QR + code
    q = 24 * mm
    draw_qr(c, VERIFY_URL.format(code=code), W - 18 * mm - q, 18 * mm, q)
    c.setFillColor(navy); c.setFont("Courier-Bold", 8.5)
    c.drawRightString(W - 18 * mm - q - 3, 24 * mm, code)
    c.setFillColor(muted); c.setFont("Helvetica", 7)
    c.drawRightString(W - 18 * mm - q - 3, 20 * mm, "Verify: ambit-irise.github.io/certificate")
    c.setFont("Helvetica", 8); c.drawString(18 * mm, 18 * mm, "Issued on " + ctx["issued"])

def font(spec):
    """A built-in font name (Helvetica-Bold) or a path to a .ttf file, registered on first use."""
    if not spec.lower().endswith((".ttf", ".otf")):
        return spec
    name = Path(spec).stem
    if name not in pdfmetrics.getRegisteredFontNames():
        path = Path(spec) if Path(spec).is_absolute() else ROOT / spec
        pdfmetrics.registerFont(TTFont(name, str(path)))
    return name

def image_template(c, W, H, ev, ctx, code):
    """A finished design as a background image, with each field drawn at a position given in
    event.json 'template'. Positions are in the pixels of 'space' (top-left origin)."""
    t = ev["template"]
    sw, sh = t["space"]
    k = W / sw
    X = lambda x: x * k
    Y = lambda y: H - y * k
    bg = Path(t["background"])
    c.drawImage(str(bg if bg.is_absolute() else ROOT / bg), 0, 0, W, H)
    for f in t["fields"]:
        text = fill(f["text"], ctx)
        if not text:
            continue
        name, size = font(f.get("font", "Helvetica-Bold")), f["size"] * k
        if f.get("max_width"):
            while c.stringWidth(text, name, size) > f["max_width"] * k and size > f["size"] * k * 0.5:
                size *= 0.97
        c.setFont(name, size); c.setFillColor(HexColor(f.get("color", "#111111")))
        draw = {"center": c.drawCentredString, "right": c.drawRightString}.get(f.get("align"), c.drawString)
        draw(X(f["x"]), Y(f["y"]), text)
    q = t["qr"]  # x, y = top-left of the QR in template pixels
    note = "Verify: ambit-irise.github.io/certificate"
    cx = X(q["x"] + q["size"] / 2)
    box_w = max(X(q["size"]), c.stringWidth(note, "Helvetica", 7.5 * k)) + 12 * k
    c.setFillColor(HexColor("#FFFFFF"))
    c.roundRect(cx - box_w / 2, Y(q["y"] + q["size"] + 30), box_w, (q["size"] + 36) * k, 6 * k, fill=1, stroke=0)
    draw_qr(c, VERIFY_URL.format(code=code), X(q["x"]), Y(q["y"] + q["size"]), X(q["size"]))
    c.setFillColor(HexColor("#111111")); c.setFont("Courier-Bold", 12 * k)
    c.drawCentredString(cx, Y(q["y"] + q["size"] + 14), code)
    c.setFont("Helvetica", 7.5 * k)
    c.drawCentredString(cx, Y(q["y"] + q["size"] + 26), note)

def make_pdf(ev, ctx, code) -> bytes:
    buf = io.BytesIO()
    if ev.get("template"):
        sw, sh = ev["template"]["space"]
        W = landscape(A4)[0]
        W, H = W, W * sh / sw
    else:
        W, H = landscape(A4)
    c = canvas.Canvas(buf, pagesize=(W, H), invariant=1)  # invariant: same input -> same bytes
    c.setTitle(f"{ctx['type']} - {ctx['name']}")
    c.setAuthor(ctx["issuer"])
    (image_template if ev.get("template") else basic_template)(c, W, H, ev, ctx, code)
    c.showPage(); c.save()
    return buf.getvalue()

# ---------------------------------------------------------------- main

def main():
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("folder", type=Path)
    ap.add_argument("--publish", action="store_true", help="write encrypted certs and records into the portal")
    a = ap.parse_args()
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")  # Windows consoles default to cp1252

    folder = a.folder.resolve()
    ev = json.loads((folder / "event.json").read_text(encoding="utf-8"))
    for k in ["prefix", "event", "type", "date", "issued"] + ([] if ev.get("template") else ["body"]):
        if not ev.get(k):
            sys.exit(f"event.json is missing '{k}'")
    # event-specific values shown on the certificate and the verification page, e.g. total time
    extras = ev.get("extra_fields", [])
    prefix = ev["prefix"].upper()
    if len(prefix) != 5 or any(ch not in ALPHABET for ch in prefix):
        sys.exit("prefix must be 5 characters from " + ALPHABET + " (no O, 0, I or 1)")

    people = read_participants(folder, extras)
    codes_path = folder / "codes.csv"
    codes = load_codes(codes_path)
    taken = {r["code"] for r in codes.values()}
    if any(not c.startswith(prefix + "-") for c in taken):
        sys.exit(f"codes.csv holds codes with a different prefix than '{prefix}'. "
                 "The prefix cannot change once codes are issued.")

    # one records file per event, named after the prefix (data/B4B26.json); the pages pick it from the code
    records_path = DATA / f"{prefix}.json"
    if records_path.exists():
        if not taken:
            sys.exit(f"{records_path.name} already exists for another event. Choose a different prefix.")
        db = json.loads(records_path.read_text(encoding="utf-8"))
    else:
        db = {"issuer": ISSUER, "records": {}, "revoked": [], "revoked_reason": {}, "version": 1}
    before = set(db["records"]) - {lookup_of(c) for c in taken}  # records not issued by this run's event
    issuer = ev.get("issuer") or db["issuer"]

    pdf_dir = folder / "pdf"
    pdf_dir.mkdir(exist_ok=True)
    out_rows, changed = [], 0
    for p in people:
        prev = codes.get(p["key"])
        code = prev["code"] if prev else new_code(prefix, taken)
        taken.add(code)
        if not prev and (lookup_of(code) in before or (CERTS / file_of(code)).exists()):
            sys.exit("Code collision with an existing certificate; run again.")
        rec = {f: p[f] for f in FIELDS}
        rec.update(type=ev["type"], event=ev["event"], date=ev["date"], issuer=issuer, issued=ev["issued"])
        if extras:
            rec["extra"] = [[x["label"], p[x["key"]]] for x in extras]
        rec["fingerprint"] = fingerprint(code, rec)
        pdf = make_pdf(ev, dict(rec, code=code, **{x["key"]: p[x["key"]] for x in extras}), code)
        safe = "".join(ch if ch.isalnum() else "_" for ch in p["name"]).strip("_")
        (pdf_dir / f"{safe}_{code}.pdf").write_bytes(pdf)
        out_rows.append({"key": p["key"], "code": code, "name": p["name"], "email": p["email"],
                         "download": f"https://ambit-irise.github.io/certificate/download.html?code={code}"})
        if a.publish:
            if lookup_of(code) in before and not prev:
                sys.exit(f"Refusing to overwrite an existing certificate ({code}).")
            k = sha("key:" + code)
            iv, ct = seal(k, json.dumps(rec, ensure_ascii=False, separators=(",", ":")).encode("utf-8"))
            new = {"ct": b64encode(ct).decode(), "iv": b64encode(iv).decode()}
            pk = sha("pdf:" + code)
            piv, pct = seal(pk, pdf)
            target = CERTS / file_of(code)
            blob = piv + pct
            if db["records"].get(lookup_of(code)) != new or not target.exists() or target.read_bytes() != blob:
                changed += 1
            db["records"][lookup_of(code)] = new
            if not target.exists() or target.read_bytes() != blob:
                target.write_bytes(blob)

    gone = [r for k, r in codes.items() if k not in {p["key"] for p in people}]
    with open(codes_path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["key", "code", "name", "email", "download"])
        w.writeheader()
        w.writerows(out_rows + [{**{k: r.get(k, "") for k in ["key", "code", "name", "email", "download"]}} for r in gone])

    print(f"{len(out_rows)} certificates for '{ev['event']}'")
    print(f"  plain PDFs : {pdf_dir}")
    print(f"  codes      : {codes_path}")
    if gone:
        print(f"  note: {len(gone)} earlier code(s) no longer in the participant list were kept in codes.csv:")
        for r in gone:
            print(f"    {r['code']}  {r['name']}")
    if a.publish:
        # same formatting as the existing files: re-running leaves unchanged entries byte-identical
        records_path.write_text(json.dumps(db, indent=1, ensure_ascii=False), encoding="utf-8", newline="\n")
        print(f"  published  : {changed} new or changed certificate(s) in data/{records_path.name} and certs/")
    else:
        print("  preview only: run again with --publish to add them to the portal")

if __name__ == "__main__":
    main()
