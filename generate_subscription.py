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

SUBSCRIPTION_TITLE = "(•˕ •マⳊДудоня VPN"
UPDATE_INTERVAL_HOURS = 12


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


def find_internal_tags(data: dict) -> set:
    """Теги outbound'ов, которые являются внутренними хопами каскада.

    Такие серверы доступны только через loopback-инбаунды (entry-tier2 и т.п.),
    то есть к ним подключается предыдущий сервер цепочки, а не клиент.
    Выставлять их отдельными серверами в подписке нельзя — они не работают.
    """
    routing = data.get("routing") or {}
    balancers = {b.get("tag"): b for b in routing.get("balancers") or []}

    # Инбаунды, на которые завёрнут loopback (внутренние точки входа каскада)
    loopback_inbounds = set()
    for outbound in data.get("outbounds") or []:
        if outbound.get("protocol") == "loopback":
            tag = (outbound.get("settings") or {}).get("inboundTag")
            if tag:
                loopback_inbounds.add(tag)

    if not loopback_inbounds:
        return set()

    # Балансировщики, доступные только изнутри каскада
    internal_balancers = set()
    entry_balancers = set()
    for rule in routing.get("rules") or []:
        balancer_tag = rule.get("balancerTag")
        if not balancer_tag:
            continue
        inbound_tags = rule.get("inboundTag") or []
        if inbound_tags and all(t in loopback_inbounds for t in inbound_tags):
            internal_balancers.add(balancer_tag)
        else:
            entry_balancers.add(balancer_tag)

    # Переходы по fallbackTag тоже ведут внутрь каскада
    changed = True
    while changed:
        changed = False
        for tag in list(internal_balancers):
            fallback = (balancers.get(tag) or {}).get("fallbackTag")
            if fallback in balancers and fallback not in internal_balancers:
                internal_balancers.add(fallback)
                changed = True

    internal_balancers -= entry_balancers
    if not internal_balancers:
        return set()

    internal_tags = set()
    for tag in internal_balancers:
        for selector in (balancers.get(tag) or {}).get("selector") or []:
            for outbound in data.get("outbounds") or []:
                out_tag = outbound.get("tag") or ""
                if out_tag.startswith(selector):
                    internal_tags.add(out_tag)

    # Тег, выбранный и внешним балансировщиком, остаётся точкой входа
    entry_tags = set()
    for tag in entry_balancers:
        for selector in (balancers.get(tag) or {}).get("selector") or []:
            for outbound in data.get("outbounds") or []:
                out_tag = outbound.get("tag") or ""
                if out_tag.startswith(selector):
                    entry_tags.add(out_tag)

    return internal_tags - entry_tags


def collect_links():
    """Читает configs/*.json и возвращает ссылки в порядке файлов в папке.

    В подписку попадают только точки входа: внутренние хопы каскадов
    (tier2/tier3) из плоского списка исключаются — напрямую они не работают.
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
            if path.stat().st_size == 0:
                print(f"[!] {path.name}: файл пустой — пропущен", file=sys.stderr)
            else:
                print(f"[!] {path.name}: битый JSON ({exc})", file=sys.stderr)
            skipped += 1
            continue

        remarks = (data.get("remarks") or path.stem).strip()
        internal_tags = find_internal_tags(data)

        vless_outbounds = []
        for outbound in data.get("outbounds") or []:
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
            if outbound.get("tag") in internal_tags:
                # Внутренний хоп каскада — только через полный JSON-конфиг
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


def collect_json_configs():
    """Полные JSON-конфиги для Happ: каскады работают только целиком."""
    configs = []
    if not CONFIG_DIR.is_dir():
        return configs
    for path in sorted(CONFIG_DIR.glob("*.json"), key=lambda p: p.name):
        try:
            data = json.loads(path.read_text(encoding="utf-8-sig"))
        except json.JSONDecodeError:
            continue
        if not data.get("remarks"):
            data["remarks"] = path.stem
        configs.append(data)
    return configs


def generate():
    links, total_files, skipped = collect_links()
    OUT_DIR.mkdir(exist_ok=True)

    # GitHub Pages не позволяет задавать HTTP-заголовки, поэтому название
    # подписки и интервал обновления передаём строками внутри тела подписки
    # (#profile-title / #profile-update-interval понимают Happ и v2rayNG).
    title_b64 = base64.b64encode(SUBSCRIPTION_TITLE.encode("utf-8")).decode("ascii")
    header = (
        f"#profile-title: base64:{title_b64}\n"
        f"#profile-update-interval: {UPDATE_INTERVAL_HOURS}\n"
    )

    plain = header + "\n".join(links) + "\n"
    encoded = base64.b64encode(plain.encode("utf-8")).decode("ascii")

    (OUT_DIR / "subscription.txt").write_text(plain, encoding="utf-8", newline="\n")
    (OUT_DIR / "sub").write_text(encoded, encoding="ascii", newline="\n")
    (OUT_DIR / "sub.txt").write_text(encoded, encoding="ascii", newline="\n")

    # Полные JSON-конфиги: единственный способ сохранить каскады
    # (tier2/tier3 через loopback и балансировщики). Happ передаёт такой
    # массив в Xray 1:1, поэтому «Белые списки» работают как задумано.
    configs = collect_json_configs()
    (OUT_DIR / "sub.json").write_text(
        json.dumps(configs, ensure_ascii=False, separators=(",", ":")),
        encoding="utf-8",
        newline="\n",
    )

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
    print(f"Готово: {OUT_DIR / 'sub.json'} (полные конфиги с каскадами)")


if __name__ == "__main__":
    main()
