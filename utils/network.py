import asyncio
import socket
import config


def apply_ipv4_only_patch() -> None:
    """Monkey-patch getaddrinfo чтобы всегда возвращать только IPv4 адреса."""
    original = socket.getaddrinfo

    def _ipv4_only(host, port, family=0, type=0, proto=0, flags=0):
        return original(host, port, socket.AF_INET, type, proto, flags)

    socket.getaddrinfo = _ipv4_only


async def get_resolved_ip(domain: str) -> str | None:
    """Резолвит домен в IPv4 адрес. До 2 попыток при сбое."""
    loop = asyncio.get_running_loop()
    for attempt in range(2):
        try:
            addrs = await loop.getaddrinfo(
                domain, 443, family=socket.AF_INET, type=socket.SOCK_STREAM
            )
            if addrs:
                return addrs[0][4][0]
        except Exception:
            if attempt == 0:
                await asyncio.sleep(0.2)
                continue
            break
    return None