"""Container supervisor and existing panel, without systemd or Docker socket access."""
import collections
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parent))


def drop_runtime_privileges():
    if os.geteuid()!=0:return
    # Docker clears effective capabilities for --user 10001. Transfer only the
    # low-port binding capability before re-executing as that unprivileged UID.
    # SETUID/SETGID are absent from the resulting process's permitted set.
    import ctypes
    libc=ctypes.CDLL(None,use_errno=True)
    class Header(ctypes.Structure):
        _fields_=[('version',ctypes.c_uint),('pid',ctypes.c_int)]
    class Data(ctypes.Structure):
        _fields_=[('effective',ctypes.c_uint),('permitted',ctypes.c_uint),('inheritable',ctypes.c_uint)]
    def checked(result):
        if result!=0:raise OSError(ctypes.get_errno(),'Could not restrict HTTPS runtime privileges')
    checked(libc.prctl(8,1,0,0,0))  # PR_SET_KEEPCAPS
    os.setgroups([]);os.setgid(10001);os.setuid(10001)
    header=Header(0x20080522,0);data=(Data*2)()
    data[0]=Data(1<<10,1<<10,1<<10)  # CAP_NET_BIND_SERVICE only
    checked(libc.capset(ctypes.byref(header),data))
    checked(libc.prctl(47,2,10,0,0))  # PR_CAP_AMBIENT_RAISE
    checked(libc.prctl(8,0,0,0,0))
    os.execv(sys.executable,[sys.executable,'-I',str(Path(__file__).resolve()),*sys.argv[1:]])


if __name__=='__main__':drop_runtime_privileges()

from atlantctl import Manager, AdminError, private_write
from control.access import entry_path, read_credentials
from control.server import PanelServer
from control.service_helper import Actions


class Core:
    def __init__(self, folder):
        self.folder=Path(folder); self.process=None
        self.lock=threading.RLock(); self.lines=collections.deque(maxlen=200)

    def set_enabled(self,value):
        path=self.folder/'client.json'
        config=json.loads(path.read_text())
        config['core_enabled']=value
        private_write(path,config)

    def start(self):
        with self.lock:
            if self.process is not None and self.process.poll() is None:
                return self.status()
            self.prepare_subscription_accounting()
            self.process=subprocess.Popen(['/usr/local/bin/atlant-server','-c',str(self.folder/'core.json')],
                                          cwd=self.folder,stdout=subprocess.PIPE,stderr=subprocess.STDOUT)
            self.set_enabled(True)
            process=self.process
            def collect():
                for raw in iter(process.stdout.readline,b''):
                    line=raw[:8192].decode(errors='replace').rstrip()
                    with self.lock: self.lines.append(line)
                    print(line,flush=True)
                process.stdout.close()
            threading.Thread(target=collect,daemon=True).start()
            return self.status()

    def prepare_subscription_accounting(self):
        # Early Docker installs omitted quota configuration, so even unlimited
        # managed subscriptions were rejected by the core. Preserve explicit
        # coordinator/worker settings when upgrading those installations.
        path=self.folder/'core.json'
        config=json.loads(path.read_text())
        if 'quota' not in config:
            config['quota']={'coordinator':True}
            private_write(path,config)

    def status(self):
        with self.lock:
            active=self.process is not None and self.process.poll() is None
            return {'active':'active' if active else 'inactive','state':'running' if active else 'dead',
                    'pid':self.process.pid if active else 0,'backend':'docker-process'}

    def stop(self,persist=True):
        with self.lock: process=self.process
        if process is not None and process.poll() is None:
            process.terminate()
            try: process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                raise AdminError('Core did not stop gracefully; container left running') from None
        if persist:self.set_enabled(False)
        return self.status()


class ContainerManager(Manager):
    def __init__(self,config,core):
        config=dict(config,service_socket='container-process')
        super().__init__(config);self.core=core

    def helper_call(self,action,body=None):
        if action=='status':return self.core.status()
        if action=='start':return self.core.start()
        if action=='stop':return self.core.stop()
        if action=='restart':self.core.stop(persist=False);return self.core.start()
        if action=='logs':
            count=(body or {}).get('lines',50)
            if type(count)is not int or not 1<=count<=200:raise AdminError('Invalid journal line limit')
            with self.core.lock:return {'logs':list(self.core.lines)[-count:],'source':'container'}
        if action in {'configcheck','configinfo','configsave'}:
            with self.core.lock:
                path=self.core.folder/'core.json'
                raw=path.read_bytes();config=json.loads(raw);revision=hashlib.sha256(raw).hexdigest()
                if action=='configinfo':return {'verified':True,'overridden_fields':[],'log_level':config.get('log_level','error'),'backend':'docker-process'}
                try:
                    if action=='configcheck':return {'patch':Actions.patch(body),'revision':revision}
                    if not isinstance(body,dict) or set(body)!={'patch','revision'} or body['revision']!=revision:
                        raise ValueError('Core configuration changed; reload before saving')
                    config.update(Actions.patch(body['patch']))
                except ValueError as error:raise AdminError(str(error)) from None
                private_write(path,config)
                return {'configuration_saved':True,'activation':'core-restart-required'}
        raise AdminError('This operation is not available in the container runtime')


def main():
    drop_runtime_privileges()
    folder=Path('/data')
    config=json.loads((folder/'client.json').read_text())
    core=Core(folder)
    state=folder/'panel'
    record=read_credentials(state/'credentials.json')
    manager=ContainerManager(config,core)
    panel=config['panel']
    server=PanelServer(('127.0.0.1',panel['port']),panel['origin'],manager,record,
                      base_path=entry_path(state),credential_loader=lambda:read_credentials(state/'credentials.json'))
    stopped=threading.Event()
    def shutdown(*_):
        if not stopped.is_set():
            stopped.set();threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,shutdown);signal.signal(signal.SIGINT,shutdown)
    if config.get('core_enabled',True):core.start()
    try:server.serve_forever(poll_interval=.25)
    finally:
        server.server_close();core.stop(persist=False)


if __name__=='__main__':main()
