PRO_SERVER_URL = "https://api.getiantem.org"
CONFIG_BASE_URL = "https://df.iantem.io/api/v1"

APP_NAME = "lantern"
DEFAULT_PLATFORM = "linux"
DEFAULT_APP_VERSION = "dev"
DEFAULT_SINGBOX_VERSION = "1.12.0"
DEFAULT_LOCALE = "en-US"
DEFAULT_COUNTRY = "IR"
DEFAULT_USER_AGENT = "lantern-subscription-exporter/1.0"

CONNECT_TIMEOUT = 15
READ_TIMEOUT = 45
RETRY_TOTAL = 3
RETRY_BACKOFF = 2.0
RETRY_STATUSES = (429, 500, 502, 503, 504)

MIN_CONFIGS = 1
MAX_CONFIGS = 200

HEADER_APP_VERSION = "X-Lantern-App-Version"
HEADER_VERSION = "X-Lantern-Version"
HEADER_PLATFORM = "X-Lantern-Platform"
HEADER_APP_NAME = "X-Lantern-App"
HEADER_DEVICE_ID = "X-Lantern-Device-Id"
HEADER_USER_ID = "X-Lantern-User-Id"
HEADER_PRO_TOKEN = "X-Lantern-Pro-Token"
HEADER_CLIENT_COUNTRY = "X-Lantern-Client-Country"
HEADER_NOISE = "X-Lantern-Rand"

ADVERTISED_PROTOCOLS = (
    "http",
    "socks",
    "mixed",
    "shadowsocks",
    "vmess",
    "trojan",
    "naive",
    "hysteria",
    "shadowtls",
    "vless",
    "tuic",
    "hysteria2",
    "anytls",
    "wireguard",
    "samizdat",
    "samizdat-reverse",
    "reflex",
    "hysteria2x",
    "meek",
    "algeneva",
    "twiddle",
    "water",
    "unbounded",
    "outline",
)

SHADOWSOCKS_METHODS = (
    "2022-blake3-aes-128-gcm",
    "2022-blake3-aes-256-gcm",
    "2022-blake3-chacha20-poly1305",
    "aes-128-gcm",
    "aes-256-gcm",
    "chacha20-ietf-poly1305",
    "xchacha20-ietf-poly1305",
)

SUBSCRIPTION_LINKS_FILE = "sub.txt"
SUBSCRIPTION_SINGBOX_FILE = "singbox.json"
URLTEST_URL = "https://www.gstatic.com/generate_204"
