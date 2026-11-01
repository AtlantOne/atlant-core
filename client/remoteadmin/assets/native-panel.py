"""Temporary SSH-owned panel session for an existing native installation."""
import json
import os
from pathlib import Path
import secrets
import signal
import socket
import sys
import threading


def main(metadata_path=Path('/opt/atlant-managed/native.json')):
    if metadata_path.is_symlink() or metadata_path.stat().st_uid!=0 or metadata_path.stat().st_mode&0o077:
        raise ValueError('Private native registration required')
    metadata=json.loads(metadata_path.read_text())
    source=Path(metadata['panel_source'])
    if source.is_symlink() or not (source/'atlantctl.py').is_file():raise ValueError('Native management source unavailable')
    sys.path.insert(0,str(source))
    from atlantctl import Manager
    from control.server import PanelServer
    from control.security import password_record
    from control.service_helper import Actions
    from control.runtime import unit_definition
    if unit_definition(metadata['unit'])[1]!=metadata['definition']:
        raise ValueError('Native service definition changed; refresh this server installation first')
    config={}
    if metadata.get('client_config'):config=json.loads(Path(metadata['client_config']).read_text())
    config.update(api_url=metadata['api_url'],api_key=metadata['api_key'],state_dir=metadata['state_dir'])
    state=Path(metadata['state_dir']);state.mkdir(mode=0o700,parents=True,exist_ok=True)
    owner=state.stat()
    if config.get('service_socket') and owner.st_uid!=0:
        # Share native panel state under its own UID, not root-owned SQLite
        # journals or preference files. Its existing narrow helper handles
        # service actions through peer-credential authentication.
        os.setgroups([]);os.setgid(owner.st_gid);os.setuid(owner.st_uid)
        os.chdir(source)
        manager=Manager(config)
    else:
        config['service_socket']='ssh-native-process'
        actions=Actions({'core_unit':metadata['unit'],'core_config':metadata['config'],
            'state_dir':str(metadata_path.parent/'native-helper'),'runtime_registration':{'definition':metadata['definition'],'overridden_fields':metadata['overridden_fields']}},root_owned=True)
        class NativeManager(Manager):
            def helper_call(self,action,body=None):return actions.execute(action,body)
        manager=NativeManager(config)
    password=secrets.token_hex(24);entry='/'+secrets.token_urlsafe(24)+'/'
    # Binding port zero avoids a race with another administrative session.
    server=PanelServer(('127.0.0.1',0),'http://127.0.0.1:19090',manager,password_record(password,'admin'),base_path=entry)
    port=server.server_address[1]
    server.origin='http://127.0.0.1:'+str(port);server.authority='127.0.0.1:'+str(port)
    print(json.dumps({'panel_port':port,'entry_path':entry,'username':'admin','password':password}),flush=True)
    def shutdown(*_):threading.Thread(target=server.shutdown,daemon=True).start()
    signal.signal(signal.SIGTERM,shutdown);signal.signal(signal.SIGHUP,shutdown)
    # OpenSSH closes stdin when its owning client disconnects. No permanent
    # second panel service or replacement administrator password is created.
    threading.Thread(target=lambda:(sys.stdin.buffer.read(),shutdown()),daemon=True).start()
    try:server.serve_forever(poll_interval=.25)
    finally:server.server_close()


if __name__=='__main__':main()
