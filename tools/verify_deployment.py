"""Synthetic deployment regressions. No local configuration queries or settings changes."""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import subprocess
import uuid
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('exe', type=Path)
parser.add_argument('--output', type=Path, default=Path('test-results'))
args = parser.parse_args()
exe = args.exe.resolve()
root = args.output.resolve() / ('deployment-' + uuid.uuid4().hex)
root.mkdir(parents=True)
results = {}

def encode(value):
    return json.dumps(value, ensure_ascii=False, separators=(',', ':')).encode('utf-8')

def make_bundle(name, files, altered=None, compression=zipfile.ZIP_DEFLATED):
    path = root / (name + '.zip')
    manifest = {'files': [{'name': n, 'size_bytes': len(b), 'sha256': hashlib.sha256(b).hexdigest()} for n, b in files.items()]}
    with zipfile.ZipFile(path, 'x', compression=compression, compresslevel=1 if compression==zipfile.ZIP_DEFLATED else None) as z:
        for n, b in files.items():
            z.writestr(n, altered[n] if altered and n in altered else b)
        z.writestr('manifest.json', encode(manifest))
    return path

def analyze(name, path, expected):
    before = hashlib.sha256(path.read_bytes()).hexdigest() if path.is_file() else None
    p = subprocess.run([str(exe), 'analyze', str(path), '--output', str(root)], capture_output=True,
                       text=True, encoding='utf-8', timeout=90)
    assert p.returncode == expected, (name, p.returncode, p.stdout, p.stderr)
    if before:
        assert hashlib.sha256(path.read_bytes()).hexdigest() == before, 'Source ZIP modified'
    reports = [v.split(': ', 1)[1] for v in p.stdout.splitlines() if v.startswith('분석 보고서: ')]
    html = Path(reports[0]).read_text('utf-8') if reports else ''
    results[name] = {'exit_code': p.returncode, 'report_created': bool(reports), 'stderr': p.stderr.strip()}
    return html

nic = {'if_index': 1, 'adapter_name': '{00000000-0000-0000-0000-000000000001}',
       'friendly_name': 'Synthetic NIC', 'description': 'Synthetic NIC', 'addresses': [],
       'filter_interface': False, 'hardware_interface': True}
snapshot = {'schema_version': 1, 'modules': [
    {'task_id': 'network', 'status': 'ok', 'adapters': [nic],
     'interfaces': [{'if_index': 1, 'oper_status': 1, 'filter_interface': False}]},
    {'task_id': 'bindings', 'status': 'ok', 'queries': [{'rows': [{
        'InstanceID': nic['adapter_name']+'::filter', 'ComponentID': 'filter',
        'ComponentClassName': 'Filter', 'Enabled': True}]}]}]}
analyze('baseline', make_bundle('baseline', {'snapshot.json': encode(snapshot)}), 0)
for key in ('enabled', 'keyword'):
    s = copy.deepcopy(snapshot)
    if key == 'enabled':
        s['modules'][1]['queries'][0]['rows'][0]['Enabled'] = None
    else:
        s['modules'].append({'task_id': 'advanced', 'status': 'ok', 'queries': [{'rows': [
            {'InstanceID': nic['adapter_name'], 'RegistryKeyword': None}]}]})
    html = analyze('null_'+key, make_bundle('null-'+key, {'snapshot.json': encode(s)}), 1)
    assert html and ('미확인 1' in html if key == 'enabled' else 'RegistryKeyword' in html)

block = b'\0' * (16*1024*1024)
large_files = {f'user-log-{i}.log': block for i in range(1, 17)}
large_files['snapshot.json'] = encode(snapshot)
archive = make_bundle('sixteen-max-logs', large_files)
del large_files, block
analyze('max_logs_zip', archive, 0)
folder = root / 'sixteen-max-logs-folder'
folder.mkdir()
with zipfile.ZipFile(archive) as z:
    for name in z.namelist():
        # All names originate in this script; extraction is streamed, never delegated to extractall.
        assert '/' not in name and '\\' not in name and ':' not in name
        with z.open(name) as source, (folder/name).open('xb') as target:
            while chunk := source.read(65536):
                target.write(chunk)
def file_hash(path):
    digest = hashlib.sha256()
    with path.open('rb') as f:
        while chunk := f.read(65536):
            digest.update(chunk)
    return digest.hexdigest()

hashes_before = {p.name: file_hash(p) for p in folder.iterdir()}
analyze('max_logs_folder', folder, 0)
hashes_after = {p.name: file_hash(p) for p in folder.iterdir()}
assert hashes_before == hashes_after, 'Source evidence modified'

small = {'snapshot.json': encode(snapshot), 'user-log-1.log': b'original log'}
analyze('bad_streamed_sha', make_bundle('bad-sha', small, {'user-log-1.log': b'altered! log'}), 2)
crc_path = make_bundle('bad-crc', small, compression=zipfile.ZIP_STORED)
bytes_ = bytearray(crc_path.read_bytes())
position = bytes_.index(b'original log')
bytes_[position] ^= 1
crc_path.write_bytes(bytes_)
analyze('bad_streamed_crc', crc_path, 2)
assert 'CRC' in results['bad_streamed_crc']['stderr']
results['exe_sha256'] = hashlib.sha256(exe.read_bytes()).hexdigest()
(root/'results.json').write_text(json.dumps(results, ensure_ascii=False, indent=2), 'utf-8')
print(json.dumps({'checks_passed': len(results)-1, 'artifacts': str(root)}, ensure_ascii=False))
