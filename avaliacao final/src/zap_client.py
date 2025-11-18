
try:
    from zapv2 import ZAPv2
except Exception:
    ZAPv2 = None

class ZapClient:
    def __init__(self, api_key=None, address='localhost', port=8080):
        self.api_key = api_key
        self.address = address
        self.port = port
        if ZAPv2:
            self.zap = ZAPv2(apikey=api_key, proxies={'http': f'http://{address}:{port}'})
        else:
            self.zap = None

    def active_scan(self, target):
        if not self.zap:
            raise RuntimeError('ZAP client not available. Install python-owasp-zap-v2.4 and run ZAP.')
        self.zap.urlopen(target)
        scan_id = self.zap.ascan.scan(target)
        return scan_id

    def get_alerts(self, baseurl):
        if not self.zap:
            return []
        return self.zap.core.alerts(baseurl=baseurl)
