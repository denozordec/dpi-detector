import re
import asyncio

import httpx
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

import config
from cli.console import console
from cli.ui import clean_hostname, build_domain_row
from core.tls_scanner import check_domain_tls, check_http_injection, create_dpi_client
from core.tcp16_scanner import check_tcp_16_20
from utils.network import get_resolved_ip


# ── Воркеры ──────────────────────────────────────────────────────────────────

async def _resolve_worker(domain_raw: str, semaphore: asyncio.Semaphore, stub_ips: set) -> dict:
    """
    Фаза 0: DNS-резолв. Возвращает начальный entry-словарь.
    dns_fake: False = чисто, True = заглушка, None = DNS FAIL (sentinel для пропуска TLS/HTTP фаз).
    """
    domain = clean_hostname(domain_raw)
    async with semaphore:
        resolved_ip = await get_resolved_ip(domain)

    entry = {
        "domain": domain,
        "resolved_ip": resolved_ip,
        "dns_fake": False,
        "t13_res": ("[dim]—[/dim]", "", 0.0),
        "t12_res": ("[dim]—[/dim]", "", 0.0),
        "http_res": ("[dim]—[/dim]", ""),
    }

    if resolved_ip is None:
        fail = "[yellow]DNS FAIL[/yellow]"
        entry["t13_res"] = (fail, "Домен не найден", 0.0)
        entry["t12_res"] = (fail, "Домен не найден", 0.0)
        entry["http_res"] = (fail, "Домен не найден")
        entry["dns_fake"] = None
    elif stub_ips and resolved_ip in stub_ips:
        fake = "[bold red]DNS FAKE[/bold red]"
        detail = f"DNS подмена -> {resolved_ip}"
        entry["t13_res"] = (fake, detail, 0.0)
        entry["t12_res"] = (fake, detail, 0.0)
        entry["http_res"] = (fake, detail)
        entry["dns_fake"] = True

    return entry


async def _tls_worker(
    entry: dict,
    client: httpx.AsyncClient,
    tls_key: str,
    semaphore: asyncio.Semaphore,
) -> None:
    """Фаза TLS: пишет результат в entry in-place. Пропускает домены с DNS-проблемами."""
    if entry["dns_fake"] is not False:
        return
    try:
        result = await check_domain_tls(entry["domain"], client, semaphore)
    except Exception:
        result = ("[dim]ERR[/dim]", "Unknown error", 0.0)
    entry[tls_key] = result


async def _http_worker(
    entry: dict,
    client: httpx.AsyncClient,
    semaphore: asyncio.Semaphore,
) -> None:
    """Фаза HTTP: пишет результат в entry in-place. Пропускает домены с DNS-проблемами."""
    if entry["dns_fake"] is not False:
        return
    async with semaphore:
        try:
            result = await check_http_injection(entry["domain"], client, semaphore)
        except Exception:
            result = ("[dim]ERR[/dim]", "Unknown error")
    entry["http_res"] = result


async def _tcp16_worker(item: dict, semaphore: asyncio.Semaphore) -> list:
    ip   = item["ip"]
    port = int(item.get("port", 443))
    sni  = None if port == 80 else (item.get("sni") or config.FAT_DEFAULT_SNI)

    alive_str, status, detail = await check_tcp_16_20(ip, port, sni, semaphore)

    asn_raw = str(item.get("asn", "")).strip()
    asn_str = (
        f"AS{asn_raw}"
        if asn_raw and not asn_raw.upper().startswith("AS")
        else asn_raw.upper()
    ) or "-"

    return [item["id"], asn_str, item["provider"], alive_str, status, detail]


# ── Хелпер для прогресс-бара ──────────────────────────────────────────────────

async def _run_with_progress(tasks: list, description: str) -> list:
    results = []
    total = len(tasks)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task_id = progress.add_task(description, total=total)
        for future in asyncio.as_completed(tasks):
            result = await future
            results.append(result)
            done = len(results)
            progress.update(task_id, completed=done, description=f"{description} ({done}/{total})...")
    return results


async def _run_phase_with_progress(tasks: list, description: str) -> None:
    """Для фаз, которые мутируют entry in-place и ничего не возвращают."""
    total = len(tasks)
    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task_id = progress.add_task(description, total=total)
        completed = 0
        for future in asyncio.as_completed(tasks):
            await future
            completed += 1
            progress.update(task_id, completed=completed, description=f"{description} ({completed}/{total})...")


# ── Тест 2: домены ────────────────────────────────────────────────────────────

async def run_domains_test(semaphore: asyncio.Semaphore, stub_ips: set, domains: list) -> dict:
    """Тест 2: TLS 1.3 → TLS 1.2 → HTTP injection. Возвращает статистику."""
    console.print("\n[bold]Проверка доменов (TLS + HTTP injection)[/bold]\n")

    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("Домен", style="cyan", no_wrap=True, width=18)
    table.add_column("TLS1.2", justify="center")
    table.add_column("TLS1.3", justify="center")
    table.add_column("HTTP",   justify="center")
    table.add_column("Детали", style="dim", no_wrap=True)

    # Фаза 0: DNS-резолв
    dns_tasks = [_resolve_worker(d, semaphore, stub_ips) for d in domains]
    entries = await _run_with_progress(dns_tasks, "Фаза 0/3: DNS-резолв...")
    entries.sort(key=lambda e: e["domain"])

    # Один клиент на фазу — SSL-контекст создаётся один раз, не на каждый домен
    client_tls13 = create_dpi_client("TLSv1.3")
    client_tls12 = create_dpi_client("TLSv1.2")
    client_http  = create_dpi_client()

    try:
        await _run_phase_with_progress(
            [_tls_worker(e, client_tls13, "t13_res", semaphore) for e in entries],
            "Фаза 1/3: TLS 1.3..."
        )
        await _run_phase_with_progress(
            [_tls_worker(e, client_tls12, "t12_res", semaphore) for e in entries],
            "Фаза 2/3: TLS 1.2..."
        )
        await _run_phase_with_progress(
            [_http_worker(e, client_http, semaphore) for e in entries],
            "Фаза 3/3: HTTP..."
        )
    finally:
        await client_tls13.aclose()
        await client_tls12.aclose()
        await client_http.aclose()

    rows = sorted([build_domain_row(e) for e in entries], key=lambda x: x[0])

    dns_fail_count = 0
    resolved_ips_counter: dict = {}
    for r in rows:
        resolved_ip = r[5] if len(r) > 5 else None
        if resolved_ip and stub_ips and resolved_ip in stub_ips:
            resolved_ips_counter[resolved_ip] = resolved_ips_counter.get(resolved_ip, 0) + 1
        if any("DNS FAIL" in r[col] for col in (1, 2, 3)):
            dns_fail_count += 1

    for r in rows:
        table.add_row(*r[:5])
    console.print(table)

    confirmed_stubs = {ip: c for ip, c in resolved_ips_counter.items() if stub_ips and ip in stub_ips}
    if confirmed_stubs or dns_fail_count > 0:
        console.print(f"\n[bold yellow][i] ВОЗМОЖНО НЕ НАСТРОЕН DoH:[/bold yellow]")
        if confirmed_stubs:
            ips_text = [f"[red]{ip}[/red] у {c} домен(ов)" for ip, c in confirmed_stubs.items()]
            console.print(f"DNS вернул IP заглушки: {', '.join(ips_text)}")
        if dns_fail_count > 0:
            console.print(f"У {dns_fail_count} сайтов обнаружен DNS FAIL (Домен не найден)")
        console.print("[yellow]Рекомендация: Настройте DoH/DoT на вашем устройстве, роутере или VPN[/yellow]\n")

    block_markers = ("TLS DPI", "TLS MITM", "TLS BLOCK", "ISP PAGE", "BLOCKED", "TCP RST", "TCP ABORT")
    return {
        "total":    len(domains),
        "ok":       sum(1 for r in rows if "OK" in r[1] or "OK" in r[2]),
        "blocked":  sum(1 for r in rows if any(m in r[1] or m in r[2] or m in r[3] for m in block_markers)),
        "timeout":  sum(1 for r in rows if "TIMEOUT" in r[1] or "TIMEOUT" in r[2]),
        "dns_fail": sum(1 for r in rows if "DNS FAIL" in r[1]),
    }


# ── Тест 3: TCP 16-20KB ───────────────────────────────────────────────────────

async def run_tcp_test(semaphore: asyncio.Semaphore, tcp_items: list) -> dict:
    """Тест 3: FAT-header TCP блокировка. Возвращает статистику."""
    console.print("\n[bold]Проверка TCP 16-20KB блока[/bold]")
    console.print(
        "[dim]SHORT (HEAD) → проверяем живость. FAT (GET + 64KB заголовок) → смотрим на блокировку.[/dim]\n"
    )

    table = Table(show_header=True, header_style="bold magenta", border_style="dim")
    table.add_column("ID",        style="white")
    table.add_column("ASN",       style="yellow")
    table.add_column("Провайдер", style="cyan")
    table.add_column("Alive",     justify="center")
    table.add_column("Статус",    justify="center")
    table.add_column("Детали",    style="dim")

    tasks = [_tcp16_worker(item, semaphore) for item in tcp_items]
    tcp_results = await _run_with_progress(tasks, "Проверка...")

    def _provider_group(provider_str: str) -> str:
        clean = re.sub(r'[^\w\s\.-]', '', provider_str).strip()
        parts = clean.split()
        return parts[0] if parts else clean

    provider_counts: dict = {}
    for row in tcp_results:
        group = _provider_group(row[2])
        provider_counts[group] = provider_counts.get(group, 0) + 1

    def _sort_key(row):
        group = _provider_group(row[2])
        try:
            id_num = int(row[0].split('-')[-1])
        except (ValueError, IndexError):
            id_num = 99999
        return (-provider_counts.get(group, 0), group, id_num)

    tcp_results.sort(key=_sort_key)

    passed  = sum(1 for r in tcp_results if "OK"       in r[4])
    blocked = sum(1 for r in tcp_results if "DETECTED" in r[4])
    mixed   = sum(1 for r in tcp_results if "MIXED"    in r[4])

    for r in tcp_results:
        table.add_row(*r[:6])
    console.print(table)

    if mixed > 0:
        console.print("[dim]Смешанные результаты указывают на балансировку DPI у провайдера[/dim]")

    return {
        "total":   len(tcp_items),
        "ok":      passed,
        "blocked": blocked,
        "mixed":   mixed,
    }