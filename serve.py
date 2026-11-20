#!/usr/bin/env python3
"""Раздаёт сгенерированную подписку по HTTP.

Запуск:  python serve.py [--port 8080] [--host 0.0.0.0]

Ссылки для VPN-клиента:
  http://<IP-компьютера>:8080/sub      - base64-подписка (v2rayNG, Happ, Hiddify...)
  http://<IP-компьютера>:8080/sub.txt  - обычный список vless:// ссылок

Подписка пересобирается из configs/ при каждом запросе, поэтому после
правки конфигов достаточно перезагрузить подписку в клиенте.
"""

import argparse
import base64
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import generate_subscription as gen

TITLE = "Скапиздончик vpn"


def lan_ips():
    ips = set()
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            ips.add(s.getsockname()[0])
    except OSError:
        pass
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            ip = info[4][0]
            if not ip.startswith("127."):
                ips.add(ip)
    except OSError:
        pass
    return sorted(ips)


class Handler(BaseHTTPRequestHandler):
    server_version = "VpnSub/1.0"

    def do_GET(self):
        path = self.path.split("?", 1)[0].rstrip("/") or "/"

        if path not in ("/", "/sub", "/sub.txt"):
            self.send_error(404, "Not found")
            return

        links, _, _ = gen.generate()
        plain = "\n".join(links) + "\n"
        encoded = base64.b64encode(plain.encode("utf-8")).decode("ascii")

        if path == "/sub":
            body = encoded.encode("ascii")
            content_type = "text/plain; charset=utf-8"
        elif path == "/sub.txt":
            body = plain.encode("utf-8")
            content_type = "text/plain; charset=utf-8"
        else:
            items = "\n".join(
                f'<li><a href="{link}">{link.split("#", 1)[-1]}</a></li>'
                for link in links
            )
            sub_url = f"http://{self.headers.get('Host', '127.0.0.1')}/sub.txt"
            happ = f"happ://add/{sub_url}"
            html = f"""<!doctype html>
<html lang="ru"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{TITLE}</title>
<h1>{TITLE}</h1>
<p>Серверов: {len(links)}</p>
<p><a href="{happ}">Добавить в Happ</a></p>
<p>Ссылка для VPN-клиента: <code>{sub_url}</code></p>
<ul>{items}</ul>
</html>"""
            body = html.encode("utf-8")
            content_type = "text/html; charset=utf-8"

        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        # Заголовки, которые читают v2rayNG / Happ / Hiddify
        self.send_header(
            "profile-title",
            "base64:" + base64.b64encode(TITLE.encode("utf-8")).decode("ascii"),
        )
        self.send_header("profile-update-interval", "12")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print(f"{self.address_string()} - {fmt % args}")


def main():
    parser = argparse.ArgumentParser(description="HTTP-сервер подписки")
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument("--host", default="0.0.0.0")
    args = parser.parse_args()

    links, total_files, skipped = gen.generate()
    print(f"Конфигов: {total_files}" + (f", с ошибками: {skipped}" if skipped else ""))
    print(f"Серверов в подписке: {len(links)}")
    print()
    print("Ссылки для VPN-клиента (пока сервер запущен):")
    for ip in lan_ips() or ["127.0.0.1"]:
        print(f"  http://{ip}:{args.port}/sub")
    print()
    print("Ctrl+C — остановить.")

    server = ThreadingHTTPServer((args.host, args.port), Handler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nОстановлено.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()

