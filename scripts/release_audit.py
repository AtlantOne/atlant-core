"""Conservative pre-publication checks. Reports locations, never secret values.

Default: inspect the Git index. --workspace: inspect non-ignored source files
with ripgrep, useful before Git initialization. Not a complete secret scanner;
test fixtures and documentation still require human review.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import subprocess

PRIVATE_NAMES = {'users.json', 'atlant_config.json', 'settings.json', 'local.properties'}
PRIVATE_SUFFIXES = {'.db', '.sqlite', '.sqlite3', '.exe', '.dll', '.so', '.aar', '.apk', '.bin', '.key'}
SECRETS = {'pbk', 'password', 'passwd', 'api_secret', 'private_key'}
ASSIGNMENT = re.compile(r'''(?i)(?:["'](?P<key>pbk|password|passwd|api_secret|private_key)["']\s*:|\b(?P<var>pbk|password|passwd|api_secret|private_key)\b\s*=)\s*(?P<quote>["'])(?P<value>[^\r\n]*?)(?P=quote)''')

# Public uTLS v1.8.2 example key, used only by upstream TLS tests. A different
# key at the same path is still rejected; this is not a directory-wide exemption.
PUBLIC_FIXTURE_KEYS = {'third_party/utls/testdata/example-key.pem':
    '4280dcaf02ddf203cc1e3179b872f2e2f130662437b2f525bb24dfab4e7fade3',
    'third_party/quic-go/internal/testdata/priv.key':
    '1a0066fcd8be2b1397002fe040bb28c221c539ef44d165556d56eb107f78c4c2',
    'third_party/quic-go/http3/internal/testdata/priv.key':
    '1a0066fcd8be2b1397002fe040bb28c221c539ef44d165556d56eb107f78c4c2'}


def placeholder(value):
    upper = value.upper()
    return (upper.startswith(('YOUR_', 'EXAMPLE_', 'CHANGE_ME', '${'))
            or value.startswith('<') and value.endswith('>'))


def inspect_file(root, relative):
    path = root / relative
    name = path.name.lower()
    findings = []
    if path.is_symlink():
        return [(relative, 0, 'symlink requires manual review')]
    fixture = PUBLIC_FIXTURE_KEYS.get(str(relative).replace('\\', '/'))
    if fixture and path.is_file() and hashlib.sha256(path.read_bytes()).hexdigest() == fixture:
        return []
    if name in PRIVATE_NAMES or path.suffix.lower() in PRIVATE_SUFFIXES or '.pre-sqlite' in name or name.endswith(('-wal', '-shm', '.db.lock')):
        return [(relative, 0, 'private data or build artifact in source set')]
    if not path.is_file() or path.stat().st_size > 2 * 1024 * 1024:
        return findings
    # Fixtures may intentionally contain known sample keys. This exception is
    # explicit, not a promise that fixtures cannot contain real credentials.
    if path.name.endswith(('_test.go', '_test.py')) or path.name.startswith('test_') or 'tests' in Path(relative).parts or ('test' in Path(relative).parts and path.name.endswith('Test.kt')):
        return findings
    try:
        text = path.read_text(encoding='utf-8')
    except (UnicodeError, OSError):
        return findings
    for number, line in enumerate(text.splitlines(), 1):
        if re.search(r'-----BEGIN (?:[A-Z0-9]+ )?PRIVATE KEY-----', line):
            findings.append((relative, number, 'private key material'))
        for match in ASSIGNMENT.finditer(line):
            if match.group('value') and not placeholder(match.group('value')):
                findings.append((relative, number, 'non-placeholder secret assignment: ' + (match.group('key') or match.group('var')).lower()))
    if path.suffix.lower() == '.json':
        try:
            value = json.loads(text)
        except ValueError:
            return findings
        def visit(item):
            if isinstance(item, dict):
                for key, child in item.items():
                    if key.lower() in SECRETS and isinstance(child, str) and child and not placeholder(child):
                        findings.append((relative, 0, 'non-placeholder JSON secret: ' + key.lower()))
                    visit(child)
            elif isinstance(item, list):
                for child in item:
                    visit(child)
        visit(value)
    return sorted(set(findings))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--workspace', action='store_true')
    parser.add_argument('--private-root', type=Path, help='Compare every inventoried file, including fixtures, against local private configuration values; never print values')
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[1]
    command = ['rg', '--files', '--hidden', '--no-require-git', '-g', '!.git/**'] if args.workspace else ['git', 'ls-files', '--cached', '-z']
    process = subprocess.run(command, cwd=root, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if process.returncode:
        print('Source inventory unavailable; audit NOT completed. Use --workspace before Git initialization.')
        return 2
    separator = '\n' if args.workspace else '\0'
    paths = [p for p in process.stdout.decode('utf-8').split(separator) if p]
    findings = sorted({finding for path in paths for finding in inspect_file(root, path)})
    if args.private_root:
        values=set()
        def collect(item):
            if isinstance(item,dict):
                for key,value in item.items():
                    normalized=key.lower().replace('_','').replace('-','')
                    if normalized in {'pbk','password','passwd','apisecret','privatekey','sshpwd','sshpassword','bottoken','token'} and isinstance(value,str) and len(value)>=16 and not placeholder(value):values.add(value.encode())
                    collect(value)
            elif isinstance(item,list):
                for child in item:collect(child)
        for name in ['settings.json','users.json','atlant_config.json']:
            path=args.private_root/name
            if path.is_file():collect(json.loads(path.read_text(encoding='utf-8-sig')))
        key=args.private_root/'atlant_server_key.bin'
        if key.is_file() and 16<=key.stat().st_size<=4096:values.add(key.read_bytes())
        for relative in paths:
            path=root/relative
            if path.is_file() and path.stat().st_size<=16*1024*1024:
                data=path.read_bytes()
                if any(value in data for value in values):findings.append((relative,0,'matches local private configuration material'))
    for path, line, reason in findings:
        print('%s:%s: %s' % (path, line, reason))
    print('Scanned %d source paths; %d findings. Values redacted. Fixtures/docs need separate review.' % (len(paths), len(findings)))
    return 1 if findings else 0


if __name__ == '__main__':
    raise SystemExit(main())
