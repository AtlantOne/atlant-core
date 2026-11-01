"""Invoked through pinned SSH; JSON configuration arrives only on stdin."""
import hashlib
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import platform
import zipfile
import urllib.request
from urllib.parse import urlsplit
from contextlib import closing

CONTAINER='atlant-managed'
IMAGE_PREFIX='atlant-managed'
NATIVE_UNIT='atlant_vpn.service'


def capture(argv,timeout=30):
    result=subprocess.run(argv,capture_output=True,text=True,timeout=timeout)
    if result.returncode:raise RuntimeError('Operation failed: '+argv[0])
    return result.stdout


def read_private(path):
    path=Path(path)
    if path.is_symlink() or not path.is_file() or path.stat().st_size>1024*1024:
        raise ValueError('Missing or unsafe installation metadata')
    value=json.loads(path.read_text())
    if not isinstance(value,dict):raise ValueError('Invalid installation metadata')
    return value


def check_database(path,config):
    import sqlite3
    path=Path(path)
    if path.is_symlink() or not path.is_file():raise ValueError('Existing user database must be regular SQLite')
    with closing(sqlite3.connect(path.as_uri()+'?mode=ro',uri=True,timeout=5)) as db:
        if db.execute('PRAGMA application_id').fetchone()[0]!=0x41544c55 or db.execute('PRAGMA user_version').fetchone()[0]!=1:
            raise ValueError('Unsupported Atlant database schema; existing installation preserved')
        if db.execute('PRAGMA quick_check').fetchone()[0]!='ok':raise ValueError('User database integrity check failed')
        tables={row[0] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
        snapshot=db.execute('SELECT snapshot FROM inbound_applied_catalog WHERE id=1').fetchone() if 'inbound_applied_catalog' in tables else None
        versions=[record['settings']['wire_version'] for record in json.loads(snapshot[0])['records'] if record['settings']['enabled']] if snapshot else [config.get('wire_version',7)]
        if config.get('legacy_wire') or any(version!=7 for version in versions):
            raise ValueError('This release requires wire7; existing clients and listeners were not changed')


def inspect_container(name):
    value=json.loads(capture(['docker','inspect','--type','container',name]))
    if not isinstance(value,list) or len(value)!=1:raise ValueError('Managed container not found')
    return value[0]


def managed_container(root):
    info=inspect_container(CONTAINER)
    source=(root/'data').resolve()
    mounts=info.get('Mounts',[])
    if not any(m.get('Type')=='bind' and Path(m.get('Source','')).resolve()==source and m.get('Destination')=='/data' for m in mounts):
        raise ValueError('Container data volume does not match this installation')
    config=info.get('Config',{})
    if config.get('Entrypoint')!=['python3','-I','/opt/atlant/management/docker_runtime.py'] and not (config.get('Entrypoint')==['python3'] and config.get('Cmd')==['-I','/opt/atlant/management/docker_runtime.py']):
        raise ValueError('This Docker container is not an Atlant managed installation')
    if info.get('State',{}).get('Paused') or info.get('State',{}).get('Restarting'):
        raise ValueError('Existing container is paused or restarting; no update performed')
    core=read_private(root/'data/core.json')
    check_database(root/'data/users.db',core)
    return info


def container_args(state,image,start=True,program=None):
    runtime=[]
    if program:
        runtime=['--workdir','/data','--env','PYTHONDONTWRITEBYTECODE=1','--env','PYTHONUNBUFFERED=1',
            '--mount','type=bind,src='+str(program/'bin/atlant-server')+',dst=/usr/local/bin/atlant-server,readonly',
            '--mount','type=bind,src='+str(program/'bin/atlant-cert-agent')+',dst=/usr/local/bin/atlant-cert-agent,readonly',
            '--mount','type=bind,src='+str(program/'management')+',dst=/opt/atlant/management,readonly','--entrypoint','python3']
    return ['docker','run' if start else 'create',*(['-d'] if start else []),'--name',CONTAINER,
        '--restart','unless-stopped','--network','host','--read-only',
        '--tmpfs','/tmp:rw,noexec,nosuid,size=32m','--cap-drop','ALL',
        '--user','0:0','--cap-add','NET_BIND_SERVICE','--cap-add','SETUID','--cap-add','SETGID',
        '--security-opt','no-new-privileges:true','--pids-limit','128',
        '--label','io.atlant.managed=1','--mount','type=bind,src='+str(state)+',dst=/data',*runtime,image,*(['-I','/opt/atlant/management/docker_runtime.py'] if program else [])]


def wait_existing(state):
    import time
    client=read_private(state/'client.json');access=read_private(state/'admin-access.json')
    url=urlsplit(client['api_url'])
    if url.scheme!='http' or url.hostname not in ('127.0.0.1','::1') or not url.port:
        raise ValueError('Managed API must be loopback HTTP')
    if client.get('core_enabled',True):
        return wait_ready(url.port,access['panel_port'],client['api_key'])
    for _ in range(60):
        try:
            with socket.create_connection(('127.0.0.1',access['panel_port']),timeout=1):return
        except OSError:time.sleep(1)
    raise RuntimeError('Updated panel did not become ready')


def update_container(root,image,settings):
    original=managed_container(root)
    old_id=original['Id'];running=original['State'].get('Running',False)
    previous=CONTAINER+'-previous-'+secrets.token_hex(6)
    renamed=False;created=False
    try:
        if running:run(['docker','stop','--time','25',CONTAINER],40)
        run(['docker','rename',CONTAINER,previous]);renamed=True
        run(container_args(root/'data',image,start=running,program=settings.get('program')));created=True
        if running:wait_existing(root/'data')
    except BaseException:
        if renamed:
            # Only remove the candidate belonging to this transaction.
            result=subprocess.run(['docker','inspect','--type','container',CONTAINER],capture_output=True,text=True,timeout=15)
            if created or result.returncode==0:
                if result.returncode==0:
                    candidate=json.loads(result.stdout)[0]
                    if candidate.get('Config',{}).get('Image')!=image:raise RuntimeError('Unexpected replacement container; rollback stopped') from None
                run(['docker','rm','-f',CONTAINER],40)
            run(['docker','rename',previous,CONTAINER])
            if running:run(['docker','start',CONTAINER],40)
        elif running:
            # A rename failure may have occurred after the graceful stop.
            run(['docker','start',old_id],40)
        raise RuntimeError('Update failed; previous container restored, persistent data retained') from None
    run(['docker','rm',previous],40)
    current=settings.get('program')
    if current:
        for mount in original.get('Mounts',[]):
            if mount.get('Destination')!='/opt/atlant/management':continue
            old=Path(mount.get('Source','')).parent
            if old!=current and (old==root/'program' or old.parent==root/'releases') and old.is_dir() and not old.is_symlink():shutil.rmtree(old)
    metadata={'format':1,'image':image,'core_commit':settings['core_commit'],'panel_commit':settings['panel_commit']}
    (root/'deployment.json').write_text(json.dumps(metadata))
    print(json.dumps({'updated':True,'running':running}),flush=True)


def run(argv,timeout=1200):
    # Package/build tools can emit arbitrary remote diagnostics; never return
    # their output into a GUI error containing credentials or private paths.
    result=subprocess.run(argv,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=timeout)
    if result.returncode:raise RuntimeError('Operation failed: '+argv[0])


def architecture(machine=None):
    machine=(machine or platform.machine()).lower()
    result={'x86_64':'amd64','amd64':'amd64','aarch64':'arm64','arm64':'arm64'}.get(machine)
    if not result:raise ValueError('No published Linux release for this server architecture: '+machine)
    return result


def download(url,limit):
    request=urllib.request.Request(url,headers={'User-Agent':'Atlant-Installer','Accept':'application/vnd.github+json' if url.startswith('https://api.github.com/') else 'application/octet-stream'})
    with urllib.request.urlopen(request,timeout=120) as response:content=response.read(limit+1)
    if len(content)>limit:raise ValueError('Release download exceeds size limit')
    return content


def release(repo,arch,target):
    base='https://api.github.com/repos/AtlantOne/atlant-'+repo
    try:metadata=json.loads(download(base+'/releases/latest',2*1024*1024))
    except urllib.error.HTTPError as error:
        if error.code!=404:raise
        published=json.loads(download(base+'/releases?per_page=1',2*1024*1024))
        if not published:raise ValueError('No published release for '+repo)
        metadata=published[0]
    tag=metadata.get('tag_name','')
    if metadata.get('draft') or not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}',tag):raise ValueError('Invalid release tag')
    name='atlant-'+repo+'-linux-'+arch+'.zip'
    assets={item['name']:item for item in metadata.get('assets',[])}
    prefix='https://github.com/AtlantOne/atlant-'+repo+'/releases/download/'+tag+'/'
    def asset(filename,limit):
        item=assets.get(filename,{})
        if item.get('browser_download_url')!=prefix+filename:raise ValueError('Published release is missing '+filename)
        value=download(item['browser_download_url'],limit)
        digest=item.get('digest')
        if digest and digest!='sha256:'+hashlib.sha256(value).hexdigest():raise ValueError('GitHub release digest mismatch')
        return value
    checksums=asset('SHA256SUMS',65536).decode('ascii')
    expected=next((line.split()[0] for line in checksums.splitlines() if len(line.split())==2 and line.split()[1].lstrip('*')==name),None)
    package=asset(name,100*1024*1024)
    if not expected or not re.fullmatch('[0-9a-fA-F]{64}',expected) or hashlib.sha256(package).hexdigest()!=expected.lower():raise ValueError('Release checksum mismatch')
    target.mkdir()
    with zipfile.ZipFile(io.BytesIO(package)) as archive:
        if len(archive.infolist())>20000 or sum(item.file_size for item in archive.infolist())>512*1024*1024:raise ValueError('Expanded release is too large')
        seen=set()
        for item in archive.infolist():
            path=Path(item.filename)
            if path.is_absolute() or '..' in path.parts or '\\' in item.filename or item.filename in seen or (item.external_attr>>16)&0o170000==0o120000:raise ValueError('Unsafe release archive')
            seen.add(item.filename);output=target/path
            if item.is_dir():output.mkdir(parents=True,exist_ok=True);continue
            output.parent.mkdir(parents=True,exist_ok=True)
            with archive.open(item) as incoming,output.open('xb') as outgoing:shutil.copyfileobj(incoming,outgoing)
            output.chmod(0o644)
    return tag


def verify_binary(path,arch):
    with path.open('rb') as stream:header=stream.read(20)
    machine={'amd64':62,'arm64':183}[arch]
    if len(header)!=20 or header[:6]!=b'\x7fELF\x02\x01' or int.from_bytes(header[18:20],'little')!=machine:raise ValueError('Release executable architecture mismatch')
    path.chmod(0o755)


def available(port,tcp=True):
    with socket.socket(socket.AF_INET,socket.SOCK_STREAM if tcp else socket.SOCK_DGRAM) as sock:
        sock.bind(('0.0.0.0',port))


def wait_ready(api_port,panel_port,secret):
    import time
    for _ in range(60):
        try:
            request=urllib.request.Request('http://127.0.0.1:'+str(api_port)+'/api/status',headers={'X-API-Key':secret})
            with urllib.request.urlopen(request,timeout=1) as response:
                if response.status!=200:raise RuntimeError('Core not ready')
            with socket.create_connection(('127.0.0.1',panel_port),timeout=1):return
        except OSError:time.sleep(1)
    raise RuntimeError('Container did not become ready; inspect it over SSH')


def install(root,destination):
    os.umask(0o077)
    if os.geteuid()!=0:raise ValueError('SSH root login is required for installation')
    settings=json.loads(sys.stdin.buffer.read(128*1024+1))
    if set(settings)-{'host','vpn_port','panel_port','password','files','core_commit','panel_commit','install_docker'}:
        raise ValueError('Unexpected installation fields')
    host=settings['host']
    if not isinstance(host,str) or not re.fullmatch(r'[A-Za-z0-9.:-]{1,253}',host):raise ValueError('Invalid public address')
    ports=[settings['vpn_port'],settings['panel_port']]
    if any(type(p)is not int or not 1024<=p<=65535 or p in (80,443) for p in ports) or len(set(ports))!=2:
        raise ValueError('Choose two distinct unprivileged ports')
    if set(settings['files'])!={'runtime.py','native-update.py','native-panel.py'}:
        raise ValueError('Invalid runtime bundle')
    for name,value in settings['files'].items():(root/name).write_text(value)
    import importlib.util
    spec=importlib.util.spec_from_file_location('atlant_native_update',root/'native-update.py')
    native=importlib.util.module_from_spec(spec);spec.loader.exec_module(native);native.UNIT=NATIVE_UNIT
    native_installation=(destination/'native.json').is_file() or not destination.exists() and shutil.which('systemctl') and native.registered()
    updating=destination.exists() and not native_installation
    if updating:
        managed_container(destination)
        print('Updating existing Docker installation',flush=True)
    elif native_installation:
        print('Updating existing native installation',flush=True)
    else:
        for port in ports:available(port)
        available(ports[0],False)
    if shutil.disk_usage('/opt').free<512*1024**2:raise ValueError('At least 512 MiB free space is required')
    arch=architecture()
    print('Downloading published '+arch+' release binaries',flush=True)
    settings['core_commit']=release('core',arch,root/'core')
    settings['panel_commit']=release('panel',arch,root/'panel')
    for name in ('atlant-server','atlant-cert-agent'):
        executable=root/'core/bin'/name
        verify_binary(executable,arch);shutil.copyfile(executable,root/name);(root/name).chmod(0o755)
    if not (root/'panel/management/atlantctl.py').is_file():raise ValueError('Panel release is incomplete')
    if native_installation:
        native.discover(root/'panel')
        native.update(root,destination,None,settings,run,check_database,capture)
        return
    if not shutil.which('docker'):
        if not settings.get('install_docker'):raise ValueError('Docker is not installed')
        if not shutil.which('apt-get'):raise ValueError('Automatic Docker installation supports Debian/Ubuntu')
        run(['apt-get','update']);run(['apt-get','install','-y','docker.io'])
        run(['systemctl','enable','--now','docker'])
    run(['docker','info'],30)
    image='python:3.14-slim-bookworm'
    print('Downloading Docker runtime',flush=True)
    run(['docker','pull',image])
    program=root/'program';program.mkdir(mode=0o755)
    shutil.copytree(root/'panel/management',program/'management');(program/'bin').mkdir(mode=0o755)
    for name in ('atlant-server','atlant-cert-agent'):shutil.copyfile(root/name,program/'bin'/name);(program/'bin'/name).chmod(0o755)
    shutil.copyfile(root/'runtime.py',program/'management/docker_runtime.py')
    for directory,subdirs,files in os.walk(program):
        Path(directory).chmod(0o755)
        for name in files:
            if Path(directory)!=program/'bin':(Path(directory)/name).chmod(0o644)
    if updating:
        releases=destination/'releases';releases.mkdir(mode=0o755,exist_ok=True)
        published=releases/secrets.token_hex(12);program.rename(published);settings['program']=published
        try:update_container(destination,image,settings)
        except BaseException:shutil.rmtree(published);raise
        return
    state=root/'data';state.mkdir(mode=0o700);panel=state/'panel';panel.mkdir(mode=0o700)
    api_port=0
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));api_port=sock.getsockname()[1]
    secret=secrets.token_hex(32);salt=secrets.token_bytes(32)
    password=settings['password']
    if not isinstance(password,str) or not 12<=len(password)<=256:raise ValueError('Invalid panel password')
    digest=hashlib.scrypt(password.encode(),salt=salt,n=16384,r=8,p=1,dklen=32)
    entry='/'+secrets.token_urlsafe(24)+'/'
    def save(path,value):path.write_text(json.dumps(value));path.chmod(0o600)
    advertise=('['+host+']') if ':' in host else host
    save(state/'core.json',{'listen':':'+str(ports[0]),'advertise_addr':advertise+':'+str(ports[0]),
        'wire_version':7,'legacy_wire':False,'sni':'www.microsoft.com','users_file':'/data/users.db',
        'server_key_file':'/data/server.key','api_addr':'127.0.0.1:'+str(api_port),'api_secret':secret,
        'subscriptions':{'enabled':False},'quota':{'coordinator':True},'log_level':'info'})
    origin='http://127.0.0.1:'+str(ports[1])
    save(state/'client.json',{'api_url':'http://127.0.0.1:'+str(api_port),'api_key':secret,'language':'en',
         'state_dir':'/data/panel','panel':{'state_dir':'/data/panel','listen':'127.0.0.1','port':ports[1],'origin':origin}})
    save(panel/'credentials.json',{'version':1,'username':'admin','salt':salt.hex(),'digest':digest.hex()})
    save(panel/'entry-path.json',{'version':1,'path':entry})
    save(state/'admin-access.json',{'panel_port':ports[1],'entry_path':entry,'username':'admin','password':password})
    for directory,subdirs,files in os.walk(state):
        os.chown(directory,10001,10001)
        for name in files:os.chown(Path(directory)/name,10001,10001)
    # Build failures leave no half-installed server. Publish persistent state
    # only after the image is ready; an existing deployment is never replaced.
    if destination.exists():raise ValueError('Managed installation already exists')
    root.rename(destination)
    state=destination/'data'
    run(container_args(state,image,program=destination/'program'))
    wait_ready(api_port,ports[1],secret)
    (destination/'deployment.json').write_text(json.dumps({'format':1,'image':image,'core_commit':settings['core_commit'],'panel_commit':settings['panel_commit']}))
    print(json.dumps({'installed':True,'panel_port':ports[1],'entry_path':entry,'username':'admin'}),flush=True)


def main(root=Path('/opt/atlant-managed')):
    import fcntl
    root=Path(root).absolute()
    if root.is_symlink():raise ValueError('Linked installation path is not supported')
    # Serialize installs to this destination, including when SSH reconnects.
    lock_path=root.parent/('.'+root.name+'.install.lock')
    descriptor=os.open(lock_path,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    # Keep the lock inode in place: unlinking it would allow a concurrent
    # installer to lock a replacement while this process still owns the old one.
    with os.fdopen(descriptor,'w') as lock:
        try:fcntl.flock(lock,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise ValueError('Installation is already running') from None
        stage=Path(tempfile.mkdtemp(prefix='.atlant-install-',dir=root.parent))
        try:install(stage,root)
        finally:
            # Only the fresh staging directory owned by this invocation.
            if stage.exists():shutil.rmtree(stage)


if __name__=='__main__':
    try:main()
    except Exception as error:
        print('Installation failed: '+str(error),file=sys.stderr)
        raise SystemExit(1)
