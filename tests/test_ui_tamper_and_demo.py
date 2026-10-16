import json
import threading
import urllib.request
import urllib.error
import pytest


def test_live_tamper_vectors_report_real_cryptographic_rejections():
    from verikernel.ui.tamper_simulator import run_adversarial_tamper_suite
    from verikernel.schemas import KernelTelemetryEvent
    result = run_adversarial_tamper_suite([KernelTelemetryEvent(seq_no=i,tid=100+i%2) for i in range(5)])
    assert len(result['attacks']) == 4
    assert all(attack['detected'] for attack in result['attacks'].values())
    assert result['attacks']['payload_bit_flip']['first_corrupted_index'] == 0
    branch = result['attacks']['payload_bit_flip']['merkle_branch']
    assert branch['before_path'][-1] != branch['after_path'][-1]
    assert result['attacks']['mid_epoch_tail_truncation']['first_corrupted_index'] == 4
    assert result['attacks']['pqc_signature_lattice_forge']['rejection']['coefficient'] == 524288


def test_offline_dashboard_and_real_http_attacks_reject_foreign_hosts(tmp_path):
    from verikernel.ui.dashboard_generator import generate_dashboard
    from verikernel.ui.server import make_server
    from html.parser import HTMLParser
    class Resources(HTMLParser):
        def __init__(self):
            super().__init__()
            self.external = []
        def handle_starttag(self,tag,attributes):
            for key,value in attributes:
                if tag in {'script','link','img'} and key in {'src','href'} and value.startswith(('http:','https:','//')):
                    self.external.append(value)
    path,data = generate_dashboard(tmp_path/'dashboard.html',work_dir=tmp_path/'cases')
    _,next_run = generate_dashboard(tmp_path/'next.html',work_dir=tmp_path/'cases')
    assert data['wal']['bundle'] != next_run['wal']['bundle']
    parser = Resources()
    parser.feed(path.read_text())
    assert parser.external == []
    server = make_server(0,path,data)
    worker = threading.Thread(target=server.serve_forever,daemon=True)
    worker.start()
    url = f'http://127.0.0.1:{server.server_port}'
    try:
        frozen = path.read_bytes()
        path.write_text('another demonstration',encoding='utf-8')
        assert urllib.request.urlopen(url).read() == frozen
        request = urllib.request.Request(url+'/api/attack',data=json.dumps({'kind':'payload_bit_flip'}).encode(),headers={'Content-Type':'application/json'})
        result = json.load(urllib.request.urlopen(request))
        assert result['detected'] and result['before_hex']!=result['after_hex']
        request = urllib.request.Request(url+'/api/status',headers={'Host':'outside.example'})
        with pytest.raises(urllib.error.HTTPError) as error:
            urllib.request.urlopen(request)
        assert error.value.code == 403
    finally:
        server.shutdown()
        server.server_close()
        worker.join()
