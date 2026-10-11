"""Verify a diagnostics archive independently using Python's ZIP and hash libraries."""
import argparse
import csv
from datetime import datetime, timezone
import hashlib
import io
import json
from pathlib import Path
import zipfile
import xml.etree.ElementTree as ET

def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as stream:
        while chunk := stream.read(65536):
            digest.update(chunk)
    return digest.hexdigest()

parser = argparse.ArgumentParser()
parser.add_argument("archive", type=Path)
args = parser.parse_args()
with zipfile.ZipFile(args.archive) as archive:
    assert archive.testzip() is None, "ZIP CRC mismatch"
    names = archive.namelist()
    assert len(names) == len(set(names)), "duplicate entries"
    assert all("/" not in n and "\\" not in n and ":" not in n and not n.startswith(".") for n in names), "unsafe entry name"
    manifest = json.loads(archive.read("manifest.json"))
    listed = {item["name"] for item in manifest["files"]}
    assert listed == set(names) - {"manifest.json"}, "manifest coverage mismatch"
    for item in manifest["files"]:
        data = archive.read(item["name"])
        assert len(data) == item["size_bytes"], item["name"]
        assert hashlib.sha256(data).hexdigest() == item["sha256"], item["name"]
    snapshot = json.loads(archive.read("snapshot.json"))
    assert snapshot["schema_version"] == 1
    rows = list(csv.DictReader(io.StringIO(archive.read("timeline.csv").decode("utf-8-sig"))))
    ordered = [row["time_utc"] for row in rows if row["time_utc"]]
    assert ordered == sorted(ordered), "timeline order mismatch"
    evidence_lines = {}
    for row in rows:
        if row["evidence_file"]:
            name = row['evidence_file']
            if name not in evidence_lines:
                evidence_lines[name] = archive.read(name).decode('utf-8').splitlines()
            evidence = evidence_lines[name]
            record = json.loads(evidence[int(row["evidence_line"]) - 1])
            assert (record.get("time_utc") or "") == row["time_utc"], "timeline evidence mismatch"
            if row["channel"] == "SDK" and row["time_utc"]:
                offset = snapshot['inputs']['log_utc_offset']
                assert offset and datetime.fromisoformat(record['original_timestamp']+offset).astimezone(timezone.utc) == datetime.fromisoformat(row['time_utc']), 'SDK source offset mismatch'
        if row["time_utc"] and row["time_local"] and row["channel"] != "SDK":
            assert datetime.fromisoformat(row["time_local"]).astimezone(timezone.utc) == datetime.fromisoformat(row["time_utc"]), "local timezone conversion mismatch"
    event_count = 0
    for name in names:
        if not (name.startswith("events-") and name.endswith(".jsonl")):
            continue
        for line in archive.read(name).decode("utf-8").splitlines():
            try:
                record = json.loads(line)
            except json.JSONDecodeError:
                assert snapshot["report_warnings"], "unreported incomplete event evidence"
                continue
            if "xml" not in record:  # Synthetic interruption fixture contains no Windows event XML.
                continue
            system = ET.fromstring(record["xml"]).find("{*}System")
            assert system is not None
            assert int(system.find("{*}EventID").text) == record["event_id"]
            assert int(system.find("{*}EventRecordID").text) == record["record_id"]
            assert system.find("{*}Provider").attrib["Name"] == record["provider"]
            original_time = datetime.fromisoformat(system.find("{*}TimeCreated").attrib["SystemTime"])
            original_time = original_time.replace(microsecond=(original_time.microsecond // 1000) * 1000)
            assert original_time == datetime.fromisoformat(record["time_utc"]), "event XML timestamp mismatch"
            event_count += 1
    for attachment in manifest.get('external_attachments', []):
        name = attachment['name']
        assert name == 'dump-attachments.zip' and name not in names, 'External attachment must remain separate'
        external = args.archive.parent / name
        if not external.exists():
            continue  # The normal bundle is valid when its optional attachment was not delivered.
        assert external.stat().st_size == attachment['size_bytes'] and file_hash(external) == attachment['sha256'], 'External attachment hash mismatch'
        with zipfile.ZipFile(external) as dumps:
            assert dumps.testzip() is None, 'Dump attachment CRC mismatch'
            dump_manifest = json.loads(dumps.read('manifest.json'))
            assert {v['name'] for v in dump_manifest['files']} == set(dumps.namelist())-{'manifest.json'}, 'Dump attachment manifest coverage'
            for item in dump_manifest['files']:
                digest = hashlib.sha256()
                size = 0
                with dumps.open(item['name']) as stream:
                    while chunk := stream.read(65536):
                        digest.update(chunk)
                        size += len(chunk)
                assert size == item['size_bytes'] and digest.hexdigest() == item['sha256'], 'Dump attachment source hash mismatch'
checksum = args.archive.with_name(args.archive.name + ".sha256")
if checksum.exists():
    assert checksum.read_text().split()[0] == hashlib.sha256(args.archive.read_bytes()).hexdigest(), "archive hash mismatch"
print(f"ZIP CRC, manifest hashes, schema, {len(rows)} timeline links and {event_count} original XML events verified.")
