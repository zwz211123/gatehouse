#!/usr/bin/env python3
"""Exercise real split processes, Unix peer credentials, OpenSSH, HTTPS and Web CRUD."""
import http.cookiejar,json,os,pathlib,pwd,queue,socket,ssl,subprocess,tempfile,threading,time,urllib.error,urllib.request
ROOT=pathlib.Path(__file__).resolve().parent.parent
BIN=pathlib.Path(os.environ.get('GHB_SMOKE_BIN',str(ROOT/'build/process')))
def port():
    with socket.socket() as s:s.bind(('127.0.0.1',0));return s.getsockname()[1]
def run(*a):return subprocess.run(a,check=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True).stdout
with tempfile.TemporaryDirectory(prefix='gatehouse-process-') as td:
    t=pathlib.Path(td);config=t/'config.json';data=t/'data';rundir=t/'run';ssh_port,web_port=port(),port();services=[];ssh=None
    run('ssh-keygen','-q','-t','ed25519','-N','','-f',str(t/'owner'))
    run('openssl','req','-x509','-newkey','rsa:2048','-keyout',str(t/'key.pem'),'-out',str(t/'cert.pem'),'-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1')
    run(str(BIN/'ghbctl'),'init','--config',str(config),'--data',str(data),'--run',str(rundir),'--user','owner','--public-key',str(t/'owner.pub'),'--public-host','127.0.0.1','--public-port',str(ssh_port),'--web-url',f'https://127.0.0.1:{web_port}','--web-listen',f'127.0.0.1:{web_port}','--tls-cert',str(t/'cert.pem'),'--tls-key',str(t/'key.pem'))
    c=json.loads(config.read_text());c.update(ssh_listen=f'127.0.0.1:{ssh_port}',ssh_user=pwd.getpwuid(os.geteuid()).pw_name,web_user=pwd.getpwuid(os.geteuid()).pw_name);config.write_text(json.dumps(c))
    logs=[]
    try:
        for role in ['core','ssh','web']:
            log=open(t/f'{role}.log','w+');logs.append(log);services.append(subprocess.Popen([str(BIN/f'ghb-{role}'),'-config',str(config)],stdout=log,stderr=log))
        for _ in range(100):
            try:
                status=json.loads(run(str(BIN/'ghbctl'),'status','--config',str(config)))
                if status['version']=='0.2.1':break
            except Exception:pass
            time.sleep(.05)
        else:raise AssertionError('core did not start')
        (t/'known').write_text(f'[127.0.0.1]:{ssh_port} '+(data/'host.pub').read_text())
        ssh=subprocess.Popen(['ssh','-T','-F','/dev/null','-p',str(ssh_port),'-i',str(t/'owner'),'-o','StrictHostKeyChecking=yes','-o',f'UserKnownHostsFile={t/"known"}','owner@127.0.0.1'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,bufsize=1)
        q=queue.Queue()
        def reader():
            for line in ssh.stdout:q.put(line)
        threading.Thread(target=reader,daemon=True).start()
        def line_with(marker):
            until=time.monotonic()+10
            while time.monotonic()<until:
                try:line=q.get(timeout=.2)
                except queue.Empty:continue
                if marker in line:return line.split(marker,1)[1].strip()
            raise AssertionError('SSH response timeout: '+marker)
        ssh.stdin.write('web login\n');ssh.stdin.flush();token=line_with('token (120秒单次): ')
        origin=f'https://127.0.0.1:{web_port}';ctx=ssl.create_default_context(cafile=str(t/'cert.pem'));jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx),urllib.request.HTTPCookieProcessor(jar))
        def req(path,body=None,code=''):
            headers={'Origin':origin};payload=None
            if body is not None:payload=body.encode() if isinstance(body,str) else json.dumps(body).encode();headers.update({'Content-Type':'application/json','X-CSRF-Token':csrf,'X-GHB-Confirmation':code})
            request=urllib.request.Request(origin+path,data=payload,headers=headers)
            try:
                with opener.open(request,timeout=10) as response:return response.status,json.load(response)
            except urllib.error.HTTPError as e:return e.code,json.load(e)
        for _ in range(100):
            try:_,challenge=req('/api/challenge');break
            except Exception:time.sleep(.05)
        else:raise AssertionError('HTTPS did not start')
        csrf=challenge['csrf'];status,result=req('/api/redeem',{'token':token});assert status==200,(status,result);assert req('/api/me')[1]['user']['name']=='owner'
        change=json.dumps({'kind':'credential','operation':'create','data':{'name':'process-created','generate':True,'enabled':True}},separators=(',',':'))
        status,result=req('/api/change',change);assert status==428,(status,result)
        ssh.stdin.write(result['command']+'\n');ssh.stdin.flush();confirmation=line_with('一次性操作确认码: ')
        status,result=req('/api/change',change,confirmation);assert status==200,(status,result);assert result['data']['public'].startswith('ssh-ed25519 ');assert 'cipher' not in result['data'];assert len(req('/api/records?kind=credential')[1])==1
        assert req('/api/change',change,confirmation)[0]==428
        source_events=[e for e in req('/api/audit')[1] if e['action']=='web.redeem']
        assert source_events and source_events[0]['source'].startswith('127.0.0.1:'),source_events
        ssh.stdin.write('exit\n');ssh.stdin.flush();ssh.wait(timeout=10)
        assert req('/api/me')[0]==401
        print(json.dumps({'split_processes':'passed','unix_peer_admin':'passed','openssh_menu':'passed','https_certificate_validation':'passed','ssh_token_web_login':'passed','web_confirmation_and_credential_generation':'passed','confirmation_replay':'denied','source_disconnect_web_revocation':'passed'},ensure_ascii=False))
    except Exception:
        for log in logs:
            log.flush();log.seek(0);print(log.read())
        raise
    finally:
        if ssh and ssh.poll() is None:ssh.kill();ssh.wait()
        for service in reversed(services):
            service.terminate()
            try:service.wait(timeout=5)
            except subprocess.TimeoutExpired:service.kill();service.wait()
        for log in logs:log.close()
