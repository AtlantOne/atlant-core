"""In-place update of a discoverable native Atlant service; user data stays put."""
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import sys
import time
from urllib.parse import urlsplit
import urllib.request

UNIT='atlant_vpn.service'
CLIENT_CONFIG=Path('/etc/atlant-control/client.json')
PANEL_APP=Path('/opt/atlant-control/management')
PANEL_AGENT=Path('/opt/atlant-control/libexec/atlant-cert-agent')
PANEL_UNITS=['atlant-control-helper.service','atlant-control.service','atlant-cert-agent.service']


def registered():
    result=subprocess.run(['systemctl','show',UNIT,'--property=LoadState','--value'],capture_output=True,text=True,timeout=15)
    return result.returncode==0 and result.stdout.strip()=='loaded'


def running(unit):
    return subprocess.run(['systemctl','is-active','--quiet',unit],capture_output=True,timeout=15).returncode==0


def discover(source):
    spec=importlib.util.spec_from_file_location('atlant_native_runtime',Path(source)/'management/control/runtime.py')
    runtime=importlib.util.module_from_spec(spec);spec.loader.exec_module(runtime)
    if running(UNIT):return runtime.inspect_unit(UNIT)
    text,fingerprint=runtime.unit_definition(UNIT)
    argv,cwd=runtime.definition_command(text)
    result,options=runtime.derive(argv,cwd,argv[0])
    config=json.loads(Path(result['config']).read_text())
    address=options.get('api-addr') or config.get('api_addr') or '127.0.0.1:8080'
    import ipaddress
    host,_,port=address.rpartition(':')
    if not ipaddress.ip_address(host.strip('[]')).is_loopback or not port.isdigit() or not 1<=int(port)<=65535:
        raise ValueError('Native API must use authenticated loopback HTTP')
    secret=options.get('api-secret') or config.get('api_secret')
    if not isinstance(secret,str) or not secret:raise ValueError('Existing native API authentication is required')
    result.update(unit=UNIT,definition=fingerprint,api_url='http://'+address,api_key=secret)
    return result


def private(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_uid!=0 or path.stat().st_mode&0o022:
        raise ValueError('Native executable/configuration must be regular and root-owned')
    if any(parent.is_symlink() for parent in path.parents):raise ValueError('Linked installation paths are not supported')
    return path


def update(stage,root,image,settings,run,check_database,capture):
    info=discover(stage/'panel')
    binary=private(info['binary']);config_path=private(info['config'])
    config=json.loads(config_path.read_text())
    def absolute(value):
        path=Path(value);return path if path.is_absolute() else Path(info['cwd'])/path
    database=absolute(config.get('users_file','users.db')).absolute()
    check_database(database,config)
    private(absolute(config.get('server_key_file','atlant_server_key.bin')))
    current_hash=hashlib.sha256(config_path.read_bytes()).hexdigest()
    binary_hash=hashlib.sha256(binary.read_bytes()).hexdigest()
    # These executables were verified against the published release checksum and CPU.
    for name in ('atlant-server','atlant-cert-agent'):
        private(stage/name)
    client_path=CLIENT_CONFIG
    client={}
    if client_path.exists():
        private(client_path);client=json.loads(client_path.read_text())
    panel_app=PANEL_APP
    has_panel=panel_app.is_dir() and client_path.exists()
    if panel_app.is_symlink():raise ValueError('Linked native panel path is not supported')
    if has_panel and (panel_app.stat().st_uid!=0 or panel_app.stat().st_mode&0o022 or any(parent.is_symlink() for parent in panel_app.parents)):
        raise ValueError('Native panel application must be root-owned and not writable by other users')
    for path in (stage/'panel/management').rglob('*'):
        if path.is_symlink():raise ValueError('Linked panel source is not supported')
        path.chmod(0o755 if path.is_dir() else 0o644)
    (stage/'panel/management').chmod(0o755)
    units=[UNIT]
    if has_panel:units+=PANEL_UNITS
    active=[unit for unit in units if running(unit)]
    replacements=[(binary,stage/'atlant-server',False)]
    if has_panel:
        replacements.append((panel_app,stage/'panel/management',True))
        agent=PANEL_AGENT
        if agent.exists():private(agent);replacements.append((agent,stage/'atlant-cert-agent',False))
    installed=[]
    stopped=[]
    new_registration=not root.exists()
    if hashlib.sha256(config_path.read_bytes()).hexdigest()!=current_hash or hashlib.sha256(binary.read_bytes()).hexdigest()!=binary_hash:
        raise ValueError('Native installation changed during the build')
    if discover(stage/'panel')['definition']!=info['definition']:raise ValueError('Native service definition changed during the build')
    try:
        for unit in reversed(active):
            stopped.append(unit);run(['systemctl','stop',unit],45)
        for target,source,directory in replacements:
            previous=target.with_name('.'+target.name+'.previous-'+secrets.token_hex(6))
            candidate=target.with_name('.'+target.name+'.candidate-'+secrets.token_hex(6))
            if directory:shutil.copytree(source,candidate)
            else:shutil.copyfile(source,candidate);candidate.chmod(0o755)
            target.rename(previous)
            try:candidate.rename(target)
            except BaseException:previous.rename(target);raise
            installed.append((target,previous,directory))
        for unit in active:run(['systemctl','start',unit],45)
        if UNIT in active:
            deadline=time.monotonic()+45
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            while True:
                try:
                    request=urllib.request.Request(info['api_url']+'/api/status',headers={'X-API-Key':info['api_key']})
                    with opener.open(request,timeout=2) as response:
                        if response.status==200:break
                except OSError:
                    if time.monotonic()>deadline:raise RuntimeError('Updated native core health check failed') from None
                    time.sleep(.5)
        # Keep the management entry separate from the installed panel's login.
        # Opening it over SSH creates a temporary session, not a password reset.
        root.mkdir(mode=0o700,exist_ok=True)
        root.chmod(0o711)
        source_target=root/'native-panel'
        next_source=root/('.native-panel-'+secrets.token_hex(6))
        shutil.copytree(stage/'panel/management',next_source)
        if source_target.exists():
            previous=source_target.with_name('.native-panel.previous-'+secrets.token_hex(6))
            source_target.rename(previous)
            try:next_source.rename(source_target)
            except BaseException:previous.rename(source_target);raise
            installed.append((source_target,previous,True))
        else:next_source.rename(source_target)
        metadata=dict(info,format=1,kind='native',panel_source=str(source_target),client_config=str(client_path) if client else '',
                      state_dir=client.get('state_dir',str(root/'native-state')),
                      core_commit=settings['core_commit'],panel_commit=settings['panel_commit'])
        record=root/'native.json';temporary=root/('.native-'+secrets.token_hex(6)+'.json')
        temporary.write_text(json.dumps(metadata));temporary.chmod(0o600);temporary.replace(record)
    except BaseException:
        if installed:
            for unit in reversed(active):
                subprocess.run(['systemctl','stop',unit],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=45)
        for target,previous,directory in reversed(installed):
            if directory:shutil.rmtree(target)
            else:target.unlink()
            previous.rename(target)
        for unit in reversed(stopped):run(['systemctl','start',unit],45)
        if new_registration and root.exists():shutil.rmtree(root)
        raise RuntimeError('Native update failed; previous application restored, user data untouched') from None
    for _,previous,directory in installed:
        if directory:shutil.rmtree(previous)
        else:previous.unlink()
    print(json.dumps({'updated':True,'kind':'native','running':UNIT in active}),flush=True)
