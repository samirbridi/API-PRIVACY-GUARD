"""No network/firewall changes. CI uses only fake binary fingerprints."""
import copy
import json
import pytest
from pathlib import Path
from api_privacy_guard.config import GuardError
from api_privacy_guard.wfp_preflight import validate_path, validate, load, fingerprint, preview

EXE = r'C:\Program Files\TestIDE\agent.exe'
BASE = {'schema_version':1,'mode':'preview_only','rules':[{
    'id':'candidateA','executable':EXE,'sha256':'a'*64,
    'protocol':'tcp','remote_ip':'8.8.8.8','remote_port':443}]}

def test_safe_preview():
    out = preview(BASE, inspect=lambda _: {'sha256':'a'*64})
    assert out['mode']=='preview_only'
    assert out['enforcement_active'] is False
    assert out['rules_created']==0 and out['traffic_blocked'] is False
    assert out['operations'][0]['layer']=='FWPM_LAYER_ALE_AUTH_CONNECT_V4'
    assert 'C:\\' not in json.dumps(out)

def test_mismatched_binary_fails():
    with pytest.raises(GuardError):
        preview(BASE, inspect=lambda _: {'sha256':'0'*64})

@pytest.mark.parametrize('path', [
    '', '/tmp/ide.exe', r'C:ide.exe', r'C:\dir\..\ide.exe',
    r'C:\dir\\ide.exe', r'C:\dir\ide.exe:stream',
    r'\\server\share\ide.exe', r'C:\dir\ide*.exe', r'C:\dir\notdll.dll'
])
def test_reject_bad_executable(path):
    with pytest.raises(GuardError):
        validate_path(path)

@pytest.mark.parametrize('fn', [
    lambda p:p.update(mode='enforce'),
    lambda p:p.update(schema_version=True),
    lambda p:p['rules'][0].update(remote_port=True),
    lambda p:p['rules'][0].update(remote_port=0),
    lambda p:p['rules'][0].update(remote_ip='192.168.1.1'),
    lambda p:p['rules'][0].update(remote_ip='127.0.0.1'),
    lambda p:p['rules'][0].update(remote_ip='0.0.0.0/0'),
    lambda p:p['rules'][0].update(protocol='icmp'),
    lambda p:p['rules'][0].update(sha256='bad'),
    lambda p:p['rules'][0].update(extra='unknown'),
])
def test_unsafe_policy_rejected(fn):
    p=copy.deepcopy(BASE)
    fn(p)
    with pytest.raises(GuardError):
        validate(p)

def test_duplicate_ids():
    p=copy.deepcopy(BASE);p['rules'].append(copy.deepcopy(p['rules'][0]))
    with pytest.raises(GuardError): validate(p)

def test_duplicate_json_keys(tmp_path):
    p=tmp_path/'p.json'
    p.write_text('{"schema_version":1,"schema_version":1,"mode":"preview_only","rules":[]}')
    with pytest.raises(GuardError): load(p)

def test_file_roundtrip(tmp_path):
    p=tmp_path/'p.json';p.write_text(json.dumps(BASE))
    assert load(p)['mode']=='preview_only'

def test_example_file_validates():
    p=Path(__file__).resolve().parents[1]/'examples'/'wfp-proposal.example.json'
    assert len(validate(load(p)))==1

def test_cli_preview(monkeypatch,tmp_path,capsys):
    import sys
    from api_privacy_guard import cli
    p=tmp_path/'p.json';p.write_text(json.dumps(BASE))
    monkeypatch.setattr('api_privacy_guard.wfp_preflight.fingerprint',lambda _: {'sha256':'a'*64})
    monkeypatch.setattr(sys,'argv',['api-privacy-guard','wfp-preview','--proposal',str(p)])
    cli.main()
    result=json.loads(capsys.readouterr().out)
    assert result['rules_created']==0
