import os
import struct
import socket
import asyncio
from typing import Tuple, List, Union
import httpx
import config
from cli.console import console

def _build_dns_query(domain: str) -> bytes:
    """Собирает бинарный пакет DNS-запроса (A-запись)."""
    tx_id = os.urandom(2)  # Случайный ID транзакции
    flags = b'\x01\x00'    # Стандартный запрос, желательна рекурсия
    qdcount = b'\x00\x01'  # 1 вопрос
    ancount = nscount = arcount = b'\x00\x00'
    header = tx_id + flags + qdcount + ancount + nscount + arcount

    qname = b''
    for part in domain.split('.'):
        qname += bytes([len(part)]) + part.encode('ascii')
    qname += b'\x00'
    qtype = b'\x00\x01'    # A record (IPv4)
    qclass = b'\x00\x01'   # IN class

    return header + qname + qtype + qclass

def _parse_dns_response(data: bytes, tx_id: bytes) -> Union[List[str], str]:
    """Разбирает бинарный ответ DNS-сервера."""
    if len(data) < 12:
        raise ValueError("Слишком короткий ответ")
    if data[:2] != tx_id:
        raise ValueError("ID транзакции не совпадает")

    flags = struct.unpack(">H", data[2:4])[0]
    rcode = flags & 0x000F
    if rcode == 3:
        return "NXDOMAIN"
    if rcode != 0:
        raise ValueError(f"RCODE ошибки: {rcode}")

    qdcount, ancount, _, _ = struct.unpack(">HHHH", data[4:12])
    offset = 12

    # Хелпер для пропуска имен (с учетом DNS-сжатия / указателей 0xC0)
    def skip_name(current_offset):
        while True:
            if current_offset >= len(data): break
            if (data[current_offset] & 0xC0) == 0xC0:
                return current_offset + 2
            length = data[current_offset]
            if length == 0:
                return current_offset + 1
            current_offset += length + 1
        return current_offset

    # Пропускаем блок Questions
    for _ in range(qdcount):
        offset = skip_name(offset)
        offset += 4  # QTYPE, QCLASS

    ips = []
    # Парсим блок Answers
    for _ in range(ancount):
        offset = skip_name(offset)
        if offset + 10 > len(data): break
        atype, aclass, ttl, rdlength = struct.unpack(">HHIH", data[offset:offset+10])
        offset += 10

        rdata = data[offset:offset+rdlength]
        offset += rdlength

        # Если это IPv4 адрес (A-запись)
        if atype == 1 and aclass == 1 and rdlength == 4:
            ips.append(socket.inet_ntoa(rdata))

    return ips if ips else "EMPTY"

class _DNSDatagramProtocol(asyncio.DatagramProtocol):
    def __init__(self):
        self.future = asyncio.get_event_loop().create_future()
    def connection_made(self, transport):
        self.transport = transport
    def datagram_received(self, data, addr):
        if not self.future.done():
            self.future.set_result(data)
    def error_received(self, exc):
        if not self.future.done():
            self.future.set_exception(exc)
    def connection_lost(self, exc):
        pass

async def _resolve_udp_native(nameserver: str, domain: str, timeout: float) -> Union[List[str], str]:
    """Отправляет UDP запрос к DNS серверу через нативный asyncio."""
    loop = asyncio.get_running_loop()
    req_data = _build_dns_query(domain)
    tx_id = req_data[:2]

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: _DNSDatagramProtocol(),
        remote_addr=(nameserver, 53)
    )
    try:
        transport.sendto(req_data)
        resp_data = await asyncio.wait_for(protocol.future, timeout)
        return _parse_dns_response(resp_data, tx_id)
    finally:
        transport.close()

# ==============================================================================
# 2. ОСНОВНАЯ ЛОГИКА И СБОРЩИКИ (Полностью асинхронные)
# ==============================================================================

async def _probe_udp_server(nameserver: str, domains: list) -> dict:
    """Параллельно резолвит домены через UDP."""
    ok = timeout_cnt = error = 0
    results = {}

    async def check_single(domain):
        try:
            res = await _resolve_udp_native(nameserver, domain, config.DNS_CHECK_TIMEOUT)
            return domain, "OK", res
        except asyncio.TimeoutError:
            return domain, "TIMEOUT", None
        except Exception:
            return domain, "ERROR", None

    # Запускаем все запросы одновременно!
    tasks = [check_single(d) for d in domains]
    completed = await asyncio.gather(*tasks)

    for domain, status, res in completed:
        if status == "OK":
            results[domain] = res
            ok += 1
        elif status == "TIMEOUT":
            results[domain] = "TIMEOUT"
            timeout_cnt += 1
        else:
            results[domain] = "ERROR"
            error += 1

    return {"ok": ok, "timeout": timeout_cnt, "error": error, "results": results}

async def _probe_doh_server(doh_url: str, domains: list) -> dict:
    """Параллельно резолвит домены через DoH."""
    ok = timeout_cnt = blocked = 0
    results = {}
    headers = {"Accept": "application/dns-json", "User-Agent": config.USER_AGENT}

    async def check_single(client, domain):
        try:
            resp = await client.get(doh_url, params={"name": domain, "type": "A"})
            if resp.status_code != 200:
                return domain, "BLOCKED", None
            data = resp.json()
            if data.get("Status") == 3:
                return domain, "NXDOMAIN", None
            ips = [a["data"] for a in data.get("Answer", []) if a.get("type") == 1]
            return domain, "OK", ips if ips else "EMPTY"
        except httpx.TimeoutException:
            return domain, "TIMEOUT", None
        except Exception:
            return domain, "BLOCKED", None

    # Одно соединение для всех запросов — это намного быстрее
    async with httpx.AsyncClient(timeout=config.DNS_CHECK_TIMEOUT, verify=False, headers=headers) as client:
        tasks = [check_single(client, d) for d in domains]
        completed = await asyncio.gather(*tasks)

    for domain, status, res in completed:
        if status == "OK":
            results[domain] = res
            ok += 1
        elif status == "NXDOMAIN":
            results[domain] = "NXDOMAIN"
            ok += 1
        elif status == "TIMEOUT":
            results[domain] = "TIMEOUT"
            timeout_cnt += 1
        else:
            results[domain] = "BLOCKED"
            blocked += 1

    return {"ok": ok, "timeout": timeout_cnt, "blocked": blocked, "results": results}

async def collect_stub_ips_silently() -> set:
    """Тихо собирает IP заглушек провайдера (если запущены только HTTP/TCP тесты)."""
    probe = None
    for udp_ip, _ in config.DNS_UDP_SERVERS:
        probe = await _probe_udp_server(udp_ip, config.DNS_CHECK_DOMAINS)
        if probe["ok"] > 0:
            break

    if not probe or not probe.get("results"):
        return set()

    ip_count: dict = {}
    for res in probe["results"].values():
        if isinstance(res, list):
            for ip in res:
                ip_count[ip] = ip_count.get(ip, 0) + 1
    return {ip for ip, count in ip_count.items() if count >= 2}

async def check_dns_integrity() -> Tuple[set, int]:
    if not config.DNS_CHECK_ENABLED:
        return set(), 0

    total = len(config.DNS_CHECK_DOMAINS)
    console.print("\n[bold]Проверка подмены DNS[/bold]")
    console.print("[dim]Проверяем, перехватывает ли провайдер DNS запросы...[/dim]\n")

    udp_probe, udp_label = None, "UDP DNS (недоступен)"
    doh_probe, doh_label = None, "DoH (недоступен)"

    with console.status("[bold cyan]Инициализация проверок...[/bold cyan]") as status:

        # ── Ищем живой UDP-сервер ─────────────────────────────────────────
        for udp_ip, udp_name in config.DNS_UDP_SERVERS:
            status.update(f"[cyan]Поиск UDP DNS:[/cyan] проверяю [yellow]{udp_ip} ({udp_name})[/yellow] ...")

            probe = await _probe_udp_server(udp_ip, config.DNS_CHECK_DOMAINS)
            bad = probe["timeout"] + probe["error"]

            if total - bad >= max(1, total // 2):
                udp_probe = probe
                udp_label = f"UDP DNS"
                console.print(f"[dim]• UDP сервер выбран: [green]{udp_ip} ({udp_name})[/green][/dim]")
                break
            else:
                console.print(f"[dim]• UDP [yellow]{udp_ip}[/yellow] недоступен (VPN или блок). Пропуск.[/dim]")

        if udp_probe is None:
            console.print("[red]× Все UDP DNS-серверы недоступны (Вероятно, заблокированы VPN или провайдером)[/red]")
            udp_probe = {"results": {d: "UNAVAIL" for d in config.DNS_CHECK_DOMAINS}}

        # ── Ищем живой DoH-сервер ─────────────────────────────────────────
        for doh_url, doh_name in config.DNS_DOH_SERVERS:
            status.update(f"[cyan]Поиск DoH DNS:[/cyan] проверяю [yellow]{doh_url} ({doh_name})[/yellow] ...")

            probe = await _probe_doh_server(doh_url, config.DNS_CHECK_DOMAINS)
            bad = probe["timeout"] + probe.get("blocked", 0)

            if total - bad >= max(1, total // 2):
                doh_probe = probe
                doh_label = f"DoH"
                console.print(f"[dim]• DoH сервер выбран: [green]{doh_url} ({doh_name})[/green][/dim]\n")
                break
            else:
                console.print(f"[dim]• DoH [yellow]{doh_name}[/yellow] недоступен. Пропуск.[/dim]")

        if doh_probe is None:
            console.print("[red]× Все DoH-серверы недоступны[/red]")
            doh_probe = {"results": {d: "UNAVAIL" for d in config.DNS_CHECK_DOMAINS}}

    # ── анализ результатов ─────────────────────────────────────────────
    dns_intercept_count = 0
    doh_blocked_count = 0
    timeout_count = 0
    udp_ips_collection: dict = {}
    rows = []

    for domain in config.DNS_CHECK_DOMAINS:
        udp_res = udp_probe["results"].get(domain)
        doh_res = doh_probe["results"].get(domain)

        udp_ips = udp_res if isinstance(udp_res, list) else None
        doh_ips = doh_res if isinstance(doh_res, list) else None

        if udp_ips:
            udp_ips_collection[domain] = udp_ips

        udp_str = ", ".join(udp_ips[:2]) if udp_ips else str(udp_res or "—")
        doh_str = ", ".join(doh_ips[:2]) if doh_ips else str(doh_res or "—")

        if udp_res == "TIMEOUT": timeout_count += 1
        if doh_res == "BLOCKED": doh_blocked_count += 1

        UDP_ERROR_MAP = {
            "TIMEOUT": "[red]× DNS ПЕРЕХВАТ[/red]",
            "NXDOMAIN": "[red]× FAKE NXDOMAIN[/red]",
            "EMPTY": "[red]× FAKE EMPTY[/red]"
        }

        if doh_ips and udp_ips:
            if set(doh_ips) == set(udp_ips):
                status = "[green]√ DNS OK[/green]"
            else:
                status = "[red]× DNS ПОДМЕНА[/red]"
                dns_intercept_count += 1
        elif doh_ips:  # Есть DoH, но нет UDP
            status = UDP_ERROR_MAP.get(udp_res, "[yellow]× UDP недоступен[/yellow]")
            if udp_res in UDP_ERROR_MAP:
                dns_intercept_count += 1
        elif udp_ips:  # Есть UDP, но нет DoH
            reason = "заблокирован" if doh_res == "BLOCKED" else "недоступен"
            status = f"[yellow]× DoH {reason}[/yellow]"
        else:
            status = "[red]× Оба недоступны[/red]"

        rows.append([domain, doh_str, udp_str, status])

    # ── детектируем заглушки ───────────────────────────────────────────
    ip_count: dict = {}
    for ips in udp_ips_collection.values():
        for ip in ips:
            ip_count[ip] = ip_count.get(ip, 0) + 1
    stub_ips = {ip for ip, cnt in ip_count.items() if cnt >= 2}

    # ── таблица ────────────────────────────────────────────────────────
    from rich.table import Table
    dns_table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    dns_table.add_column("Домен", style="cyan")
    dns_table.add_column(doh_label, style="dim")
    dns_table.add_column(udp_label, style="dim")
    dns_table.add_column("Статус")
    for row in rows:
        dns_table.add_row(*row)
    console.print(dns_table)
    console.print()

    # ── Шаг 6: диагностика ────────────────────────────────────────────────────
    if dns_intercept_count > 0:
        console.print("[bold red][!] Ваш интернет-провайдер перехватывает DNS-запросы[/bold red]")
        console.print("Провайдер подменяет ответы UDP DNS на заглушки или ложные NXDOMAIN/EMPTY\n")
        console.print(
            "[bold yellow]ВНИМАНИЕ: Это независимая проверка и она не использует ваши настроенные DNS![/bold yellow]\n"
            "[bold yellow]Рекомендация:[/bold yellow] Настройте DoH на устройстве и роутере\n"
            "[bold green]Если DoH уже настроен — игнорируйте эту проверку.[bold green]\n"
        )
    if doh_blocked_count > 0:
        console.print("[bold red][!] DoH заблокирован[/bold red] — провайдер блокирует зашифрованный DNS\n")

    return stub_ips, dns_intercept_count