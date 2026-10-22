#!/usr/bin/env python3
"""Test the packaged HTTPS entry even when the test host forbids Unix sockets."""
import json,pathlib,socket,ssl,subprocess,tempfile,time,urllib.error,urllib.request
ROOT=pathlib.Path(__file__).resolve().parent.parent
with tempfile.TemporaryDirectory(prefix='gatehouse-tls-') as td:
 t=pathlib.Path(td)
 subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',str(t/'key.pem'),'-out',str(t/'cert.pem')],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
 with socket.socket() as s:s.bind(('127.0.0.1',0));port=s.getsockname()[1]
 config={'public_host':'127.0.0.1','data':str(t/'data'),'run':str(t/'run'),'web_listen':f'127.0.0.1:{port}','web_url':f'https://127.0.0.1:{port}','tls_cert':str(t/'cert.pem'),'tls_key':str(t/'key.pem')}
 (t/'config.json').write_text(json.dumps(config));binary=ROOT/'build/amd64/gatehouse-web/usr/lib/gatehouse/ghb-web';p=subprocess.Popen([str(binary),'-config',str(t/'config.json')],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
 try:
  url=f'https://127.0.0.1:{port}/';trusted=ssl.create_default_context(cafile=str(t/'cert.pem'))
  for _ in range(100):
   try:urllib.request.urlopen(url,context=trusted,timeout=1)
   except urllib.error.HTTPError as e:
    assert e.code==503;assert json.loads(e.read())['error']=='core unavailable';break
   except urllib.error.URLError:time.sleep(.05)
  else:raise AssertionError('HTTPS did not start')
  try:urllib.request.urlopen(url,timeout=3)
  except urllib.error.URLError as e:assert isinstance(e.reason,ssl.SSLCertVerificationError),e
  else:raise AssertionError('untrusted TLS certificate accepted')
  print('Packaged HTTPS entry: trusted certificate accepted, untrusted certificate rejected, missing core fails closed with HTTP 503.')
 finally:p.terminate();p.wait(timeout=5)
