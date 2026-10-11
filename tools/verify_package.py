"""Development gate: inspect final customer ZIP, hashes, metadata and document contents."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import zipfile

parser = argparse.ArgumentParser()
parser.add_argument('archive', type=Path)
args = parser.parse_args()
archive = args.archive.resolve()
base = archive.stem
expected = {'FetchNetworkConfig.exe', 'FetchNetworkConfig.exe.sha256', 'README.md',
            'RELEASE_STATUS.json', 'docs/READ_ONLY_CONTRACT.md', 'docs/RELEASE_NOTES.md',
            'licenses/NOTICE.md', 'licenses/json-LICENSE.MIT', 'licenses/miniz-LICENSE.txt'}
with zipfile.ZipFile(archive) as z:
    assert z.testzip() is None, 'ZIP CRC mismatch'
    names = z.namelist()
    assert len(names) == len(set(names)), 'Duplicate package entries'
    assert set(names) == {base + '/' + name for name in expected}, 'Unexpected customer package contents'
    read = lambda name: z.read(base + '/' + name)
    status = json.loads(read('RELEASE_STATUS.json').decode('utf-8-sig'))
    exe_hash = hashlib.sha256(read('FetchNetworkConfig.exe')).hexdigest()
    assert status['schema_version'] == 1 and status['exe_sha256'] == exe_hash
    assert read('FetchNetworkConfig.exe.sha256').decode('ascii').split()[0] == exe_hash
    assert base == 'FetchNetworkConfig-' + status['tool_version'] + '-win-x64'
    for name in ('README.md', 'docs/READ_ONLY_CONTRACT.md', 'docs/RELEASE_NOTES.md'):
        text = read(name).decode('utf-8-sig').lower()
        for private in ('vt_pc_thrp', 'asus_x13', 'f9c14261', 'f7c3fe26', 'c:\\users\\', 'orca\\projects'):
            assert private not in text, 'Internal/customer identifier in ' + name
    expanded_exe = archive.with_suffix('') / 'FetchNetworkConfig.exe'
    assert hashlib.sha256(expanded_exe.read_bytes()).hexdigest() == exe_hash, 'Expanded EXE differs from archive'

assert archive.with_name(archive.name + '.sha256').read_text('ascii').split()[0] == hashlib.sha256(archive.read_bytes()).hexdigest()
env = dict(os.environ, FNC_VERIFY_EXE=str(expanded_exe))
ps = r"$ErrorActionPreference='Stop'; $v=(Get-Item -LiteralPath $env:FNC_VERIFY_EXE).VersionInfo; $s=Get-AuthenticodeSignature -LiteralPath $env:FNC_VERIFY_EXE; @{file_version=$v.FileVersion;product_version=$v.ProductVersion;publisher=$v.CompanyName;signature_status=[string]$s.Status} | ConvertTo-Json -Compress"
proc = subprocess.run(['powershell.exe', '-NoProfile', '-NonInteractive', '-Command', ps],
                      env=env, capture_output=True, text=True, encoding='utf-8', timeout=30)
assert proc.returncode == 0, 'File metadata inspection failed'
metadata = json.loads(proc.stdout)
assert metadata['product_version'] == status['tool_version']
assert metadata['file_version'] == status['file_version'] and metadata['publisher'] == status['publisher_display_name']
assert metadata['signature_status'] == status['signature_status'] and metadata['signature_status'] in ('Valid', 'NotSigned')
print(json.dumps({'package_verified': True, 'version': status['tool_version'],
                  'signature': metadata['signature_status'], 'environment_validation': status['environment_validation']}, ensure_ascii=False))
