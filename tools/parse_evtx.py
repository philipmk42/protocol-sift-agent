#!/usr/bin/env python3
"""
parse_evtx.py - Parse a Windows .evtx file into clean JSONL records.

Leans on SIFT's evtx_dump.py for the binary->XML conversion, then extracts
the fields we care about for triage. Every record keeps its source file and
EventRecordID so any downstream finding is traceable to an exact event.

Usage:
    python3 parse_evtx.py "<path to .evtx>" [output.jsonl]
"""
import sys, os, re, json, subprocess
import xml.etree.ElementTree as ET

# Windows event XML uses this namespace on every tag; strip it for sanity.
NS = "{http://schemas.microsoft.com/win/2004/08/events/event}"

def strip_ns(tag):
    return tag.replace(NS, "")

def dump_xml(evtx_path):
    """Run SIFT's evtx_dump.py and return its XML text."""
    result = subprocess.run(
        ["evtx_dump.py", evtx_path],
        capture_output=True, text=True
    )
    if result.returncode != 0:
        sys.exit(f"evtx_dump.py failed: {result.stderr.strip()}")
    return result.stdout

def parse_events(xml_text, source_file):
    """Yield one dict per <Event> block."""
    # evtx_dump emits a declaration + multiple <Event> blocks. Wrap them
    # so it's a single well-formed XML document we can parse.
    wrapped = "<Events>" + re.sub(r"<\?xml.*?\?>", "", xml_text) + "</Events>"
    # The stream already has an <Events> wrapper in some versions; guard it.
    wrapped = wrapped.replace("<Events><Events>", "<Events>").replace("</Events></Events>", "</Events>")
    root = ET.fromstring(wrapped)

    for ev in root.iter(f"{NS}Event"):
        rec = {"source_file": os.path.basename(source_file)}

        system = ev.find(f"{NS}System")
        if system is not None:
            for child in system:
                tag = strip_ns(child.tag)
                if tag == "EventID":
                    rec["event_id"] = (child.text or "").strip()
                elif tag == "TimeCreated":
                    rec["timestamp"] = child.get("SystemTime", "")
                elif tag == "EventRecordID":
                    rec["record_id"] = (child.text or "").strip()
                elif tag == "Computer":
                    rec["computer"] = (child.text or "").strip()

        # Collect all EventData text into one blob, then pull account + IP.
        data_blob = ""
        edata = ev.find(f"{NS}EventData")
        if edata is not None:
            for d in edata.iter(f"{NS}Data"):
                if d.text:
                    data_blob += d.text + " "
        rec["raw_data"] = data_blob.strip()

        # Source IP often shows up as "[CLIENT: x.x.x.x]" or a plain IP.
        ip = re.search(r"CLIENT:\s*([0-9]{1,3}(?:\.[0-9]{1,3}){3})", data_blob)
        if not ip:
            ip = re.search(r"\b([0-9]{1,3}(?:\.[0-9]{1,3}){3})\b", data_blob)
        rec["source_ip"] = ip.group(1) if ip else None

        # First <string> in MSSQL 18456 is the login name.
        acct = re.search(r"<string>([^<]+)</string>", data_blob)
        rec["account"] = acct.group(1).strip() if acct else None

        yield rec

def main():
    if len(sys.argv) < 2:
        sys.exit("Usage: parse_evtx.py <file.evtx> [output.jsonl]")
    evtx_path = sys.argv[1]
    out_path = sys.argv[2] if len(sys.argv) > 2 else "parsed_events.jsonl"

    xml_text = dump_xml(evtx_path)
    count = 0
    with open(out_path, "w") as f:
        for rec in parse_events(xml_text, evtx_path):
            f.write(json.dumps(rec) + "\n")
            count += 1
    print(f"Parsed {count} events -> {out_path}")

if __name__ == "__main__":
    main()
