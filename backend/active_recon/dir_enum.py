import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

DIRECTORY_WORDLIST = [
    # Generic high-value paths
    "admin",
    "admin.php",
    "login",
    "login.php",
    "dashboard",
    "index.php",
    "config.php",
    "db.php",
    "test.php",
    "info.php",
    "phpinfo.php",
    "upload.php",
    "register.php",
    "logout.php",
    "reset.php",
    "backup",
    "backups",
    "uploads",
    "files",
    "server-status",
    ".env",
    ".git",
    ".git/config",
    "robots.txt",
    "sitemap.xml",

    # API related
    "api",
    "api/v1",
    "api/v2",
    "api.php",

    # WordPress specific
    "wp-admin",
    "wp-login.php",
    "wp-content",
    "wp-content/uploads",
    "wp-content/plugins",
    "wp-content/themes",
    "wp-includes",
    "wp-json",
    "wp-config.php",
    "xmlrpc.php"
]

# ---- TUNABLE LIMITS (VERY IMPORTANT) ----
MAX_WORKERS = 20        # keep low to avoid bans
REQUEST_TIMEOUT = 4
ALLOWED_STATUS = {200, 301, 302, 401, 403}

def classify_path(path: str):
    path = path.lower()

    if "wp-" in path or "wordpress" in path:
        return "wordpress"

    if "admin" in path or "dashboard" in path:
        return "admin"

    if path.endswith(".php") and ("login" in path or "auth" in path):
        return "authentication"

    if "api" in path or "json" in path:
        return "api"

    if "config" in path or ".env" in path:
        return "config"

    if "backup" in path or "bak" in path:
        return "backup"

    if ".git" in path:
        return "repository"

    return "public"

def _check_url(url: str):
    try:
        r = requests.get(
            url,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=False,
            headers={"User-Agent": "WebRecon"}
        )

        if r.status_code in ALLOWED_STATUS:
            path = url.split("/", 3)[-1]
            return {
                "url": url,
                "status_code": r.status_code,
                "tag": classify_path(path)
            }
    except Exception:
        return None
    return None

def dir_enum(domain: str):
    """
    Large wordlist-safe directory enumeration.
    Handles thousands of paths without freezing backend.
    """

    found = []
    targets = []

    for scheme in ("http", "https"):
        base = f"{scheme}://{domain}"
        for path in DIRECTORY_WORDLIST:
            targets.append(f"{base}/{path}")

    tested = 0

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = [
            executor.submit(_check_url, url)
            for url in targets
        ]

        for future in as_completed(futures):
            tested += 1
            result = future.result()
            if result:
                found.append(result)

    return {
        "method": "http_directory_bruteforce",
        "wordlist_size": len(DIRECTORY_WORDLIST),
        "total_tested": tested,
        "found": found,
        "count": len(found)
    }