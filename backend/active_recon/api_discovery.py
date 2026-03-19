import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

API_PATHS = [
    "api",
    "api/v1",
    "api/v2",
    "api/v3",
    "v1",
    "v2",
    "v3",
    "rest",
    "rest/api",
    "services",
    "graphql",
    "graphql/playground",
    "swagger",
    "swagger.json",
    "openapi.json",
    "v3/api-docs"
]

HEADERS = {
    "User-Agent": "WebRecon",
    "Accept": "application/json"
}

TIMEOUT = 4
VALID_STATUS = {200, 401, 403}


def _check_api(url: str):
    try:
        r = requests.get(
            url,
            headers=HEADERS,
            timeout=TIMEOUT,
            allow_redirects=False
        )

        content_type = r.headers.get("Content-Type", "").lower()

        if r.status_code in VALID_STATUS:
            if "json" in content_type or "graphql" in content_type:
                return {
                    "endpoint": url,
                    "status_code": r.status_code,
                    "content_type": content_type
                }

            # GraphQL often responds even with errors
            if "graphql" in url and r.status_code in VALID_STATUS:
                return {
                    "endpoint": url,
                    "status_code": r.status_code,
                    "content_type": content_type or "graphql"
                }

    except Exception:
        return None

    return None


def api_discovery(domain: str):
    """
    Detects REST / GraphQL / OpenAPI endpoints.
    """

    discovered = []
    targets = []

    for scheme in ("http", "https"):
        base = f"{scheme}://{domain}"
        for path in API_PATHS:
            targets.append(f"{base}/{path}")

    with ThreadPoolExecutor(max_workers=20) as executor:
        futures = [
            executor.submit(_check_api, url)
            for url in targets
        ]

        for future in as_completed(futures):
            result = future.result()
            if result:
                discovered.append(result)

    return {
        "method": "heuristic_api_detection",
        "total_tested": len(targets),
        "found": discovered,
        "count": len(discovered)
    }
