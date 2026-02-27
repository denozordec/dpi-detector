import os
import ssl
import asyncio
from typing import Tuple, Optional

import config


def _make_tls_ctx() -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    return ctx


async def _open_connection(ip: str, port: int, sni: Optional[str] = None):
    """
    port == 80 → plain TCP, иначе → TLS с server_hostname=sni.
    Бросает исключения — вызывающий классифицирует сам.
    """
    if port == 80:
        return await asyncio.wait_for(
            asyncio.open_connection(ip, port),
            timeout=config.FAT_CONNECT_TIMEOUT,
        )
    ctx = _make_tls_ctx()
    return await asyncio.wait_for(
        asyncio.open_connection(ip, port, ssl=ctx, server_hostname=sni),
        timeout=config.FAT_CONNECT_TIMEOUT,
    )


def _build_short_request(ip: str, port: int) -> bytes:
    host = ip if port in (80, 443) else f"{ip}:{port}"
    return (
        f"HEAD / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode()


def _build_fat_request(ip: str, port: int) -> bytes:
    """GET-запрос с жирным заголовком X-Data размером FAT_HEADER_KB * 512 hex-байт."""
    fat_value = os.urandom(config.FAT_HEADER_KB * 512).hex()
    host = ip if port in (80, 443) else f"{ip}:{port}"
    return (
        f"GET / HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        f"Connection: close\r\n"
        f"X-Data: {fat_value}\r\n"
        f"\r\n"
    ).encode()


def _parse_http_status(data: bytes) -> int:
    if not data.startswith(b"HTTP/"):
        return 0
    parts = data.split(b" ", 2)
    if len(parts) < 2:
        return 0
    try:
        return int(parts[1])
    except ValueError:
        return 0


async def _do_short(ip: str, port: int, sni: Optional[str] = None) -> Tuple[bool, str]:
    """
    HEAD-запрос для проверки живости хоста.
    Возвращает (alive, alive_str). alive=True если получили любой HTTP статус.
    """
    try:
        reader, writer = await _open_connection(ip, port, sni)
    except asyncio.TimeoutError:
        return False, "No (timeout)"
    except Exception:
        return False, "No (conn err)"

    try:
        writer.write(_build_short_request(ip, port))
        await asyncio.wait_for(writer.drain(), timeout=config.FAT_CONNECT_TIMEOUT)

        try:
            chunk = await asyncio.wait_for(reader.read(512), timeout=config.FAT_READ_TIMEOUT)
            status = _parse_http_status(chunk)
            if status:
                return True, f"Yes ({status})"
            elif chunk:
                return True, "Yes (non-HTTP)"
            else:
                return False, "No (empty)"
        except asyncio.TimeoutError:
            return False, "No (timeout)"
    except Exception:
        return False, "No (err)"
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _do_fat(ip: str, port: int, sni: Optional[str] = None) -> Tuple[str, str]:
    """
    GET с жирным заголовком (~64KB). Отправляем чанками, чтобы знать точку обрыва.
    Возвращает (status, detail).
    """
    try:
        reader, writer = await _open_connection(ip, port, sni)
    except asyncio.TimeoutError:
        return "[red]TIMEOUT[/red]", "Handshake timeout: connect timeout"
    except ssl.SSLError as e:
        return "[red]TLS ERR[/red]", f"TLS: {str(e)[:40]}"
    except ConnectionRefusedError:
        return "[red]REFUSED[/red]", "Connection refused"
    except OSError as e:
        return "[red]OS ERR[/red]", f"errno={e.errno}"
    except Exception as e:
        return "[red]ERR[/red]", type(e).__name__

    bytes_sent = 0
    try:
        payload = _build_fat_request(ip, port)
        total = len(payload)
        chunk_size = 4096
        offset = 0

        try:
            while offset < total:
                end = min(offset + chunk_size, total)
                writer.write(payload[offset:end])
                await asyncio.wait_for(writer.drain(), timeout=config.FAT_READ_TIMEOUT)
                bytes_sent += end - offset
                offset = end
        except asyncio.TimeoutError:
            kb = bytes_sent // 1024
            return "[bold red]DETECTED[/bold red]", f"Dropped (timeout) at {kb}KB"
        except (ConnectionResetError, BrokenPipeError, OSError) as e:
            kb = bytes_sent // 1024
            tag = "RST" if "reset" in str(e).lower() else "write err"
            return "[bold red]DETECTED[/bold red]", f"Dropped ({tag}) at {kb}KB — TCP RST"

        try:
            chunk = await asyncio.wait_for(reader.read(512), timeout=config.FAT_READ_TIMEOUT)
            if _parse_http_status(chunk) or chunk:
                return "[green]OK[/green]", f"{bytes_sent // 1024}/{config.FAT_HEADER_KB}KB sent"
            else:
                kb = bytes_sent // 1024
                return "[bold red]DETECTED[/bold red]", f"Dropped (FIN) at {kb}KB — no response"
        except asyncio.TimeoutError:
            kb = bytes_sent // 1024
            return "[bold red]DETECTED[/bold red]", f"Dropped (timeout) at {kb}KB — no response"
        except (ConnectionResetError, OSError):
            kb = bytes_sent // 1024
            return "[bold red]DETECTED[/bold red]", f"Dropped (RST) at {kb}KB — TCP RST"

    except Exception as e:
        return "[red]ERR[/red]", f"{type(e).__name__} at {bytes_sent // 1024}KB"
    finally:
        try:
            writer.close()
        except Exception:
            pass


async def _fat_probe(ip: str, port: int, sni: Optional[str] = None) -> Tuple[str, str, str]:
    """SHORT alive-check → если жив, FAT-проверка. Возвращает (alive_str, status, detail)."""
    alive, alive_str = await _do_short(ip, port, sni)

    if not alive:
        return alive_str, "[yellow]UNREACHABLE[/yellow]", "Host not responding"

    fat_status, fat_detail = await _do_fat(ip, port, sni)
    return alive_str, fat_status, fat_detail


async def check_tcp_16_20(
    ip: str, port: int, sni: Optional[str], semaphore: asyncio.Semaphore
) -> Tuple[str, str, str]:
    """
    TCP_16_20_CHECK_RETRIES попыток fat-probe.
    Возвращает (alive_str, status, detail) с приоритетом DETECTED.
    """
    results = []
    for attempt in range(config.TCP_16_20_CHECK_RETRIES):
        async with semaphore:
            alive_str, status, detail = await _fat_probe(ip, port, sni)
        results.append((alive_str, status, detail))
        if attempt < config.TCP_16_20_CHECK_RETRIES - 1:
            await asyncio.sleep(0.15)

    for item in results:
        if "DETECTED" in item[1]:
            return item

    for item in results:
        if "OK" not in item[1] and "UNREACHABLE" not in item[1]:
            return item

    return results[0]