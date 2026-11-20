#!/usr/bin/env python3
"""Собирает подписку для VPN-клиентов из конфигов Xray в папке configs/.

Каждый VLESS-outbound превращается в стандартную share-ссылку vless://...
Результат:
  output/subscription.txt  - обычный список ссылок (по одной в строке)
  output/sub          - тот же список в base64 (формат подписки для
                        v2rayNG / Happ / Hiddify / Streisand и др.)
"""

import base64
import json
import sys
from pathlib import Path
from urllib.parse import quote, unquote, urlencode

ROOT = Path(__file__).resolve().parent
CONFIG_DIR = ROOT / "configs"
OUT_DIR = ROOT / "output"

# Порядок вывода серверов в подписке — как файлы лежат в папке configs/
SKIP_PROTOCOLS = {"freedom", "blackhole", "loopback", "dns"}


def build_vless_link(outbound: dict, name: str) -> str:
    """Превращает VLESS-outbound Xray в share-ссылку vless://..."""
    stream = outbound.get("streamSettings") or {}
    vnext = outbound["settings"]["vnext"][0]
    user = vnext["users"][0]

    address = vnext["address"]
    port = int(vnext["port"])
    net = stream.get("network", "tcp")
    security = stream.get("security", "none")

    params = {
        "type": net,
        "security": security,
        "encryption": user.get("encryption", "none"),
    }
    if user.get("flow"):
        params["flow"] = user["flow"]

    if security == "reality":
        reality = stream.get("realitySettings") or {}
        if reality.get("serverName"):
            params["sni"] = reality["serverName"]
        if reality.get("fingerprint"):
            params["fp"] = reality["fingerprint"]
        if reality.get("publicKey"):
            params["pbk"] = reality["publicKey"]
        if reality.get("shortId"):
            params["sid"] = reality["shortId"]
        if reality.get("spiderX"):
            params["spx"] = reality["spiderX"]
    elif security == "tls":
        tls = stream.get("tlsSettings") or {}
        if tls.get("serverName"):
            params["sni"] = tls["serverName"]
        if tls.get("fingerprint"):
            params["fp"] = tls["fingerprint"]
        if tls.get("alpn"):
            params["alpn"] = ",".join(tls["alpn"])

    # Транспорт
    if net == "xhttp":
        xhttp = stream.get("xhttpSettings") or {}
        if xhttp.get("host"):
            params["host"] = xhttp["host"]
        if xhttp.get("path"):
            params["path"] = xhttp["path"]
        if xhttp.get("mode"):
            params["mode"] = xhttp["mode"]
        extra = {
            k: v
            for k, v in xhttp.items()
            if k not in ("host", "path", "mode")
        }
        if extra:
            params["extra"] = json.dumps(extra, separators=(",", ":"))
    elif net == "ws":
        ws = stream.get("wsSettings") or {}
        if ws.get("host"):
            params["host"] = ws["host"]
        if ws.get("path"):
            params["path"] = ws["path"]
    elif net == "grpc":
        grpc = stream.get("grpcSettings") or {}
        if grpc.get("serviceName"):
            params["serviceName"] = grpc["serviceName"]
    elif net == "httpupgrade":
        hu = stream.get("httpupgradeSettings") or {}
        if hu.get("host"):
            params["host"] = hu["host"]
        if hu.get("path"):
            params["path"] = hu["path"]

    params = {k: v for k, v in params.items() if v not in (None, "")}
    query = urlencode(params, quote_via=quote, safe="")
    return f"vless://{user['id']}@{address}:{port}?{query}#{quote(name)}"


def dedupe_key(outbound: dict):
    stream = outbound.get("streamSettings") or {}
    vnext = outbound["settings"]["vnext"][0]
    user = vnext["users"][0]
    reality = stream.get("realitySettings") or {}
    tls = stream.get("tlsSettings") or {}
    xhttp = stream.get("xhttpSettings") or {}
    return (
        vnext["address"],
        int(vnext["port"]),
        user.get("id"),
        user.get("flow"),
        stream.get("network"),
        stream.get("security"),
        reality.get("publicKey"),
        reality.get("shortId"),
        tls.get("serverName"),
        xhttp.get("host"),
        xhttp.get("path"),
        xhttp.get("mode"),
    )


def collect_links():
    """Читает configs/*.json и возвращает ссылки в порядке файлов в папке.

    Дубликаты не удаляются: если один и тот же сервер встречается в нескольких
    конфигах, в подписке он будет столько же раз.
    """
    if not CONFIG_DIR.is_dir():
        sys.exit(f"Не найдена папка с конфигами: {CONFIG_DIR}")

    files = sorted(CONFIG_DIR.glob("*.json"), key=lambda p: p.name)
    if not files:
        sys.exit(f"В {CONFIG_DIR} нет .json файлов")

    links = []
    used_names = set()
    skipped = 0

    for path in files:
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError as exc:
            print(f"[!] {path.name}: битый JSON ({exc})", file=sys.stderr)
            skipped += 1
            continue

        remarks = (data.get("remarks") or path.stem).strip()
        outbounds = data.get("outbounds") or []

        vless_outbounds = []
        for outbound in outbounds:
            protocol = outbound.get("protocol")
            if protocol in SKIP_PROTOCOLS:
                continue
            if protocol != "vless":
                print(
                    f"[!] {path.name}: пропущен outbound {outbound.get('tag')} "
                    f"({protocol}) — поддерживается только VLESS",
                    file=sys.stderr,
                )
                continue
            try:
                outbound["settings"]["vnext"][0]
            except (KeyError, IndexError):
                print(f"[!] {path.name}: пустой vnext у {outbound.get('tag')}", file=sys.stderr)
                continue
            vless_outbounds.append(outbound)

        total = len(vless_outbounds)
        for index, outbound in enumerate(vless_outbounds, start=1):
            # Название без адреса сервера. Если серверов в конфиге несколько,
            # добавляем порядковый номер, чтобы они различались в клиенте.
            name = remarks if total == 1 else f"{remarks} {index}"

            # Одинаковые названия в разных файлах — уточняем именем файла
            if name in used_names:
                candidate = f"{name} ({path.stem})"
                counter = 2
                while candidate in used_names:
                    candidate = f"{name} ({path.stem} {counter})"
                    counter += 1
                name = candidate
            used_names.add(name)

            links.append(build_vless_link(outbound, name))

    return links, len(files), skipped


def generate():
    links, total_files, skipped = collect_links()
    OUT_DIR.mkdir(exist_ok=True)

    plain = "\n".join(links) + "\n"
    encoded = base64.b64encode(plain.encode("utf-8")).decode("ascii")

    (OUT_DIR / "subscription.txt").write_text(plain, encoding="utf-8", newline="\n")
    (OUT_DIR / "sub").write_text(encoded, encoding="ascii", newline="\n")
    (OUT_DIR / "sub.txt").write_text(encoded, encoding="ascii", newline="\n")

    return links, total_files, skipped


def main():
    links, total_files, skipped = generate()

    print(f"Обработано файлов: {total_files}" + (f", с ошибками: {skipped}" if skipped else ""))
    print(f"Серверов в подписке: {len(links)}")
    for link in links:
        name = unquote(link.split("#", 1)[-1])
        print(f"  - {name}")
    print()
    print(f"Готово: {OUT_DIR / 'subscription.txt'}")
    print(f"Готово: {OUT_DIR / 'sub'} (base64-подписка)")


if __name__ == "__main__":
    main()
