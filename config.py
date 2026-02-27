"""
Конфигурация DPI Detector
"""

# === Основные настройки ===
USE_IPV4_ONLY = True
MAX_CONCURRENT = 70

# === Таймауты ===
TIMEOUT = 7.0
TIMEOUT_TCP_16_20 = 10.0

# === Повторные попытки ===
DOMAIN_CHECK_RETRIES = 1
TCP_16_20_CHECK_RETRIES = 1

# === TCP блокировка ===
TCP_BLOCK_MIN_KB = 1
TCP_BLOCK_MAX_KB = 69
FAT_DEFAULT_SNI = "example.com"

# === Отображение ===
SHOW_DATA_SIZE = False
BODY_INSPECT_LIMIT = 8192
DATA_READ_THRESHOLD = 70 * 1024

# === User Agent ===
USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36"

# === Маркеры блокировок HTTP ===
BLOCK_MARKERS = [
    "lawfilter", "warning.rt.ru", "blocked", "access-denied",
    "eais", "zapret-info", "rkn.gov.ru", "mvd.ru"
]

BODY_BLOCK_MARKERS = [
    "blocked", "заблокирован", "запрещён", "запрещен", "ограничен",
    "единый реестр", "роскомнадзор", "rkn.gov.ru",
    "nap.gov.ru", "eais.rkn.gov.ru", "warning.rt.ru",
    "blocklist", "решению суда",
]

# === Windows-специфичные errno коды ===
WSAECONNRESET = 10054
WSAECONNREFUSED = 10061
WSAETIMEDOUT = 10060
WSAENETUNREACH = 10051
WSAEHOSTUNREACH = 10065
WSAECONNABORTED = 10053
WSAENETDOWN = 10050
WSAEACCES = 10013

# === DNS проверка ===
DNS_CHECK_ENABLED = True
DNS_CHECK_TIMEOUT = 5.0
DNS_CHECK_DOMAINS = [
    "rutor.info",
    "ej.ru",
    "flibusta.is",
    "clubtone.do.am",
    "rezka.ag",
    "shikimori.one",
    "youtube.com"
]

DNS_UDP_SERVERS = [
    ("8.8.8.8",        "Google"),
    ("1.1.1.1",        "Cloudflare"),
    ("9.9.9.9",        "Quad9"),
    ("94.140.14.14",   "AdGuard"),
    ("77.88.8.8",      "Yandex"),
    ("223.5.5.5",      "Alibaba"),
    ("208.67.222.222", "OpenDNS"),    # Cisco
    ("76.76.2.0",      "ControlD"),
    ("194.242.2.2",    "Mullvad"),
]

DNS_DOH_SERVERS = [
   ("https://8.8.8.8/resolve",              "Google"),
   ("https://dns.google/resolve",           "Google"),
   ("https://1.1.1.1/dns-query",            "Cloudflare"),
   ("https://cloudflare-dns.com/dns-query", "Cloudflare"),
   ("https://one.one.one.one/dns-query",    "Cloudflare"),
   ("https://dns.adguard-dns.com/resolve",  "AdGuard"),
   ("https://dns.alidns.com/resolve",       "Alibaba"),
]