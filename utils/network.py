import asyncio
import socket
from typing import Optional

from core.dns_scanner import _resolve_udp_native

_system_dns: Optional[str] = None

def _get_system_dns() -> str:
    global _system_dns
    if _system_dns is not None:
        return _system_dns

    try:
        # Пытаемся получить DNS из настроек ОС (в Linux/Docker это обычно 127.0.0.11)
        with open('/etc/resolv.conf', 'r') as f:
            for line in f:
                line = line.strip()
                if line.startswith('nameserver'):
                    parts = line.split()
                    if len(parts) >= 2:
                        ip = parts[1]
                        if ip.count('.') == 3:  # простая проверка на IPv4
                            _system_dns = ip
                            return _system_dns
    except Exception:
        pass

    _system_dns = '8.8.8.8'
    return _system_dns


async def get_resolved_ip(domain: str, family: int = socket.AF_INET) -> Optional[str]:
    """
    Резолвит домен в IP-адрес без использования блокирующих потоков (ThreadPoolExecutor).
    Использует системный DNS через чистый асинхронный UDP запрос.
    """
    if family == getattr(socket, 'AF_INET6', 10):
        loop = asyncio.get_running_loop()
        for attempt in range(2):
            try:
                addrs = await asyncio.wait_for(
                    loop.getaddrinfo(domain, 443, family=family, type=socket.SOCK_STREAM),
                    timeout=3.0
                )
                if addrs:
                    return addrs[0][4][0]
            except Exception:
                if attempt == 0:
                    await asyncio.sleep(0.2)
                    continue
                break
        return None

    ns = _get_system_dns()
    for attempt in range(2):
        try:
            res = await _resolve_udp_native(ns, domain, timeout=2.0)
            if isinstance(res, list) and res:
                return res[0]
            if res in ("NXDOMAIN", "EMPTY"):
                return None
        except Exception:
            if attempt == 0:
                await asyncio.sleep(0.2)
                continue
            break
        return None