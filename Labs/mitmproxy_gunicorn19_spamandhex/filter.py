from mitmproxy import http
import re

def request(flow):
    if 'flag' in flow.request.url or re.match(r'^http://127.0.0.1:8000/[a-z._/]*$', flow.request.url) is None:
        flow.response = http.HTTPResponse.make(418, b"I'm a teapot!")
