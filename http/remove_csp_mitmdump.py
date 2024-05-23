# 1) cambiare flow.request.host in vittima | eg 127.0.0.1
# 2) cambiare flow.request.port in porta | eg 9000
# 3) mitmdump -p 10000 -s proxy_script.py
# 4) fare richiesta al proxy 127.0.0.1:10000/pagina.php

from mitmproxy import http

def request(flow: http.HTTPFlow) -> None:

    # Modifica l'URL della richiesta
    flow.request.host = "127.0.0.1"
    flow.request.port = 9000
    #flow.request.path = "/pagina.php"

def response(flow: http.HTTPFlow) -> None:
    flow.response.content = flow.response.content.replace(b"<meta http-equiv=\"Content-Security-Policy\">", b"")
    # Rimuovi l'header CSP dalla risposta
    if "Content-Security-Policy" in flow.response.headers:
        del flow.response.headers["Content-Security-Policy"]
    #print(flow.response.headers)
    if b"Content-Security-Policy" in flow.response.content:
    	flow.response.content = flow.response.content.replace(b"Content-Security-Policy", b"\" /><img src=x onerror=alert(document.domain) />")
    print(flow.response.content)
