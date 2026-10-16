"""Server."""
from __future__ import annotations
import json
import logging
import threading
import urllib.request
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import urlsplit
from .dashboard_generator import generate_dashboard
from .tamper_simulator import run_adversarial_tamper_suite


def make_server(port: int=8765,dashboard: object=None,data: object=None) -> object:
    """Create a loopback HTTP server for the dashboard and local endpoints. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    if dashboard is None or data is None:
        dashboard,data = generate_dashboard()
    document = dashboard.read_bytes()
    class Handler(BaseHTTPRequestHandler):
        """Handler. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
        def log_message(self,format: object,*args: object) -> None:
            """Keep the local HTTP request logger quiet. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
            logging.getLogger('verikernel.ui').info(format,*args)

        def send(self,value: object,status: int=200,content_type: str='application/json') -> None:
            """Write a framed HTTP response with the requested content type. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
            body = value if isinstance(value,bytes) else json.dumps(value).encode()
            self.send_response(status)
            self.send_header('Content-Type',content_type)
            self.send_header('Content-Length',str(len(body)))
            self.send_header('X-Content-Type-Options','nosniff')
            self.send_header('Content-Security-Policy',"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; img-src data:")
            self.end_headers()
            self.wfile.write(body)

        def local(self) -> bool:
            """Reject requests that do not originate from the local interface. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
            expected = {f'127.0.0.1:{self.server.server_port}',f'localhost:{self.server.server_port}'}
            origin = self.headers.get('Origin')
            if self.headers.get('Host') not in expected or origin and (urlsplit(origin).scheme!='http' or urlsplit(origin).netloc not in expected):
                self.send({'error':'local origin required'},403)
                return False
            return True

        def do_GET(self) -> None:
            """Serve the dashboard or a supported read-only JSON endpoint. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
            if not self.local():
                return
            if self.path=='/':
                self.send(document,content_type='text/html; charset=utf-8')
            elif self.path=='/api/status':
                self.send({'live_verification':True,'attacks':list(data['tamper']['attacks'])})
            elif self.path=='/favicon.ico':
                self.send(b'',204)
            else:
                self.send({'error':'unknown resource'},404)

        def do_POST(self) -> None:
            """Run a supported local demonstration and return its result. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
            if not self.local():
                return
            if self.path!='/api/attack':
                self.send({'error':'unknown operation'},404)
                return
            try:
                length = int(self.headers.get('Content-Length','0'))
                if not 0<length<=4096 or self.headers.get_content_type()!='application/json':
                    raise ValueError('a bounded JSON body is required')
                request = json.loads(self.rfile.read(length))
                kind = request['kind']
                if kind not in data['tamper']['attacks']:
                    raise ValueError('unknown attack')
                suite = run_adversarial_tamper_suite(data['wal']['bundle'])
                self.send(suite['attacks'][kind])
            except (ValueError,KeyError,TypeError,OSError) as error:
                self.send({'error':str(error)},400)
    return ThreadingHTTPServer(('127.0.0.1',port),Handler)


def serve(port: int=8765,self_test: bool=False) -> object:
    """Run the local dashboard server until it is stopped. Complexity: O(n + W) time and O(n + M) space; n is traversed data, W delegated work, M retained delegated state."""
    server = make_server(port)
    if self_test:
        worker = threading.Thread(target=server.serve_forever,daemon=True)
        worker.start()
        url = f'http://127.0.0.1:{server.server_port}'
        try:
            status = json.load(urllib.request.urlopen(url+'/api/status',timeout=10))
            results = {}
            for kind in status['attacks']:
                request = urllib.request.Request(url+'/api/attack',data=json.dumps({'kind':kind}).encode(),headers={'Content-Type':'application/json'})
                results[kind] = json.load(urllib.request.urlopen(request,timeout=10))['detected']
            if not all(results.values()):
                raise AssertionError('a live attack escaped detection')
            return {'live_http':True,'attacks':results}
        finally:
            server.shutdown()
            server.server_close()
            worker.join()
    try:
        print(f'VeriKernel local dashboard: http://127.0.0.1:{server.server_port}',flush=True)
        server.serve_forever()
    except KeyboardInterrupt:
        logging.getLogger('verikernel.ui').info('Local server stopped')
    finally:
        server.server_close()
    return {'stopped':True}
