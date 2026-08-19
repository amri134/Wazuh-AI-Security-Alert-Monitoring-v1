import os
import json

from dotenv import load_dotenv
from playwright.sync_api import sync_playwright


# ============================================================
# CONFIG
# ============================================================

load_dotenv()


WAZUH_URL = os.getenv(
    "WAZUH_URL",
    "https://81vodocw9i1d.cloud.wazuh.com"
).rstrip("/")

WAZUH_USERNAME = os.getenv("WAZUH_USERNAME")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")

WAZUH_HOST_ID = os.getenv(
    "WAZUH_HOST_ID",
    "1"
)


# ============================================================
# LOGIN DASHBOARD
# ============================================================

def login_dashboard(page):

    print()
    print("=" * 70)
    print("[1] LOGIN WAZUH DASHBOARD")
    print("=" * 70)

    login_url = (
        f"{WAZUH_URL}/app/login"
    )

    page.goto(
        login_url,
        wait_until="domcontentloaded",
        timeout=60_000
    )

    print(
        "URL:",
        page.url
    )


    username = page.locator(
        'input[placeholder="Username"]'
    )

    password = page.locator(
        'input[placeholder="Password"]'
    )


    print(
        "[2] Menunggu form login..."
    )


    try:

        username.wait_for(
            state="visible",
            timeout=60_000
        )

        password.wait_for(
            state="visible",
            timeout=60_000
        )

    except Exception:

        print(
            "[ERROR] Form login tidak ditemukan."
        )

        return False


    print(
        "[3] Mengisi credential..."
    )

    username.fill(
        WAZUH_USERNAME
    )

    password.fill(
        WAZUH_PASSWORD
    )


    login_button = page.locator(
        'button[type="submit"]'
    )


    if login_button.count() > 0:

        login_button.click()

    else:

        password.press(
            "Enter"
        )


    try:

        page.wait_for_url(
            lambda url:
                "/app/login" not in url,
            timeout=60_000
        )

    except Exception:

        print(
            "[ERROR] Login gagal."
        )

        return False


    print()
    print(
        "[SUCCESS] Login berhasil."
    )

    print(
        "Dashboard:",
        page.url
    )


    page.wait_for_timeout(
        3000
    )

    return True


# ============================================================
# QUERY WAZUH ALERTS
# ============================================================

def get_latest_alerts(
    context,
    limit=10,
    hours=24
):

    print()
    print("=" * 70)
    print("[4] QUERY WAZUH ALERTS")
    print("=" * 70)

    url = (
        f"{WAZUH_URL}"
        "/internal/search/opensearch"
    )


    # ========================================================
    # QUERY
    #
    # Dokumentasi resmi Wazuh:
    # POST /wazuh-alerts*/_search
    #
    # Pada dashboard cloud, request diteruskan lewat
    # /internal/search/opensearch
    # ========================================================

    query_body = {

        "size": limit,

        "from": 0,

        # Alert terbaru dahulu
        "sort": [
            {
                "timestamp": {
                    "order": "desc",
                    "unmapped_type": "date"
                }
            }
        ],

        # Kita hanya membutuhkan field tertentu.
        "_source": {
            "includes": [

                "timestamp",

                "agent.id",
                "agent.name",
                "agent.ip",

                "manager.name",

                "rule.id",
                "rule.level",
                "rule.description",
                "rule.groups",
                "rule.firedtimes",

                "location",

                "decoder.name",

                "full_log",

                "data"
            ]
        },

        "query": {

            "bool": {

                "must": [],

                "filter": [

                    # Hanya alert 24 jam terakhir
                    {
                        "range": {

                            "timestamp": {

                                "gte":
                                    f"now-{hours}h",

                                "lte":
                                    "now"
                            }
                        }
                    }

                ],

                "should": [],

                "must_not": []
            }
        }
    }


    payload = {

        "params": {

            # HAR Dashboard Wazuh Cloud Anda
            # menggunakan nama index pattern ini.
            "index":
                "wazuh-alerts",

            "body":
                query_body
        }
    }


    headers = {

        "Content-Type":
            "application/json",

        "osd-xsrf":
            "osd-fetch"
    }


    print(
        "Endpoint:",
        url
    )

    print(
        "Index:",
        "wazuh-alerts"
    )

    print(
        "Limit:",
        limit
    )

    print(
        "Range:",
        f"{hours} jam terakhir"
    )


    try:

        response = (
            context.request.post(
                url,
                headers=headers,
                data=payload,
                timeout=30_000
            )
        )

    except Exception as error:

        print()
        print(
            "[ERROR] Request alert gagal:"
        )

        print(error)

        return []


    print()
    print(
        "HTTP:",
        response.status
    )


    # ========================================================
    # RESPONSE JSON
    # ========================================================

    try:

        result = response.json()

    except Exception:

        print()
        print(
            "[ERROR] Response bukan JSON."
        )

        print(
            response.text()[:5000]
        )

        return []


    if not response.ok:

        print()
        print(
            "[ERROR] OpenSearch query gagal."
        )

        print(
            json.dumps(
                result,
                indent=4,
                ensure_ascii=False
            )
        )

        return []


    # ========================================================
    # DASHBOARD RESPONSE
    #
    # {
    #   "rawResponse": {
    #       "hits": {
    #           "hits": [...]
    #       }
    #   }
    # }
    # ========================================================

    raw_response = result.get(
        "rawResponse",
        {}
    )


    hits_data = raw_response.get(
        "hits",
        {}
    )


    hits = hits_data.get(
        "hits",
        []
    )


    print()
    print(
        "[SUCCESS] Alert ditemukan:",
        len(hits)
    )


    return hits


# ============================================================
# FORMAT ALERT
# ============================================================

def print_alerts(hits):

    print()
    print("=" * 70)
    print("LATEST WAZUH ALERTS")
    print("=" * 70)


    if not hits:

        print()
        print(
            "Tidak ada alert ditemukan."
        )

        return


    for number, hit in enumerate(
        hits,
        start=1
    ):

        source = hit.get(
            "_source",
            {}
        )


        agent = source.get(
            "agent",
            {}
        )


        rule = source.get(
            "rule",
            {}
        )


        manager = source.get(
            "manager",
            {}
        )


        decoder = source.get(
            "decoder",
            {}
        )


        print()
        print(
            "-" * 70
        )

        print(
            f"ALERT #{number}"
        )

        print(
            "-" * 70
        )


        print(
            "Timestamp   :",
            source.get(
                "timestamp",
                "-"
            )
        )


        print(
            "Agent ID    :",
            agent.get(
                "id",
                "-"
            )
        )


        print(
            "Agent Name  :",
            agent.get(
                "name",
                "-"
            )
        )


        print(
            "Agent IP    :",
            agent.get(
                "ip",
                "-"
            )
        )


        print(
            "Manager     :",
            manager.get(
                "name",
                "-"
            )
        )


        print(
            "Rule ID     :",
            rule.get(
                "id",
                "-"
            )
        )


        print(
            "Rule Level  :",
            rule.get(
                "level",
                "-"
            )
        )


        print(
            "Description :",
            rule.get(
                "description",
                "-"
            )
        )


        print(
            "Groups      :",
            rule.get(
                "groups",
                []
            )
        )


        print(
            "Fired Times :",
            rule.get(
                "firedtimes",
                "-"
            )
        )


        print(
            "Location    :",
            source.get(
                "location",
                "-"
            )
        )


        print(
            "Decoder     :",
            decoder.get(
                "name",
                "-"
            )
        )


        full_log = source.get(
            "full_log"
        )


        if full_log:

            print()
            print(
                "Full Log:"
            )

            print(
                full_log[:1000]
            )


        data = source.get(
            "data"
        )


        if data:

            print()
            print(
                "Data:"
            )

            print(
                json.dumps(
                    data,
                    indent=4,
                    ensure_ascii=False
                )
            )


    print()
    print(
        "=" * 70
    )


# ============================================================
# MAIN
# ============================================================

def main():

    if not WAZUH_USERNAME:

        raise RuntimeError(
            "WAZUH_USERNAME belum tersedia."
        )


    if not WAZUH_PASSWORD:

        raise RuntimeError(
            "WAZUH_PASSWORD belum tersedia."
        )


    print()
    print("=" * 70)
    print("WAZUH ALERT RETRIEVAL")
    print("=" * 70)


    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=False
        )


        context = browser.new_context(
            ignore_https_errors=True
        )


        page = context.new_page()


        try:

            # =================================================
            # LOGIN
            # =================================================

            if not login_dashboard(page):

                print(
                    "\n[STOP] Login gagal."
                )

                return


            # =================================================
            # ALERTS
            # =================================================

            alerts = get_latest_alerts(
                context=context,
                limit=10,
                hours=24
            )


            # =================================================
            # DISPLAY
            # =================================================

            print_alerts(
                alerts
            )


        finally:

            print()
            print(
                "Menutup Chromium..."
            )

            browser.close()


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    main()