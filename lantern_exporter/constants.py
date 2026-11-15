PRO_SERVER_URL = "https://api.getiantem.org"
CONFIG_BASE_URL = "https://df.iantem.io/api/v1"

APP_NAME = "lantern"
DEFAULT_PLATFORM = "linux"
DEFAULT_APP_VERSION = "10.0.5"
DEFAULT_SINGBOX_VERSION = "v1.14.2-lantern.3"
DEFAULT_LOCALE = "en-US"
DEFAULT_COUNTRY = "IR"
DEFAULT_USER_AGENT = "lantern-subscription-exporter/2.0"

CONNECT_TIMEOUT = 15
READ_TIMEOUT = 45
CONFIG_ATTEMPTS = 3
RETRY_BASE_DELAY = 5.0
RETRY_JITTER = 3.0
RETRY_MAX_DELAY = 60.0
RETRY_AFTER_CAP = 120.0
RETRY_STATUSES = (429, 500, 502, 503, 504)

MIN_CONFIGS = 1
MAX_CONFIGS = 1000

DEFAULT_STATE_FILE = "state/lantern-state.enc"
DEFAULT_LEGACY_STATE_FILE = ".state/state.json"
STATE_KEY_ENV = "LANTERN_STATE_ENCRYPTION_KEY"
BOOTSTRAP_MODES = ("none", "create", "recreate", "migrate")
HYSTERIA2_LINK_MODES = ("omit", "include")
DEFAULT_HYSTERIA2_LINKS = "omit"

HEADER_APP_VERSION = "X-Lantern-App-Version"
HEADER_VERSION = "X-Lantern-Version"
HEADER_PLATFORM = "X-Lantern-Platform"
HEADER_APP_NAME = "X-Lantern-App"
HEADER_DEVICE_ID = "X-Lantern-Device-Id"
HEADER_USER_ID = "X-Lantern-User-Id"
HEADER_PRO_TOKEN = "X-Lantern-Pro-Token"
HEADER_CLIENT_COUNTRY = "X-Lantern-Client-Country"
HEADER_NOISE = "X-Lantern-Rand"

ADVERTISED_PROTOCOLS = ("shadowsocks", "vless", "hysteria2x")

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
SUBSCRIPTION_XRAY_FILE = "xray.json"
URLTEST_URL = "https://www.gstatic.com/generate_204"

PROFILE_NAME = "👽 Anonymous Lantern 🚀"
URLTEST_NAME = "👽 Anonymous Lantern 🌐"
IRAN_RULES_BASE_URL = "https://raw.githubusercontent.com/Chocolate4U/Iran-sing-box-rules/rule-set/"
