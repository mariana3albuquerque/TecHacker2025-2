
from scanner import run_scan

def test_dry_run():
    res = run_scan('https://example.com?q=test', dry_run=True)
    assert 'note' in res

def test_structure():
    res = run_scan('https://example.com?q=test', dry_run=True)
    assert 'vulnerabilities' in res
    assert res['url'].startswith('https://')
