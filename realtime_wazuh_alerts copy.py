import os
import json
import time
import signal
from pathlib import Path
from datetime import datetime

from dotenv import load_dotenv
from playwright.sync_api import sync_playwright


# ============================================================
# LOAD CONFIG
# ============================================================

load_dotenv()


WAZUH_URL = os.getenv(
    "WAZUH_URL",
    "https://81vodocw9i1d.cloud.wazuh.com"
).rstrip("/")

WAZUH_USERNAME = os.getenv("WAZUH_USERNAME")
WAZUH_PASSWORD = os.getenv("WAZUH_PASSWORD")

POLL_INTERVAL = int(
    os.getenv(
        "WAZUH_POLL_INTERVAL",
        "10"
    )
)

QUERY_WINDOW_MINUTES = int(
    os.getenv(
        "WAZUH_QUERY_WINDOW_MINUTES",
        "5"
    )
)

QUERY_LIMIT = int(
    os.getenv(
        "WAZUH_QUERY_LIMIT",
        "100"
    )
)

HEADLESS = (
    os.getenv(
        "WAZUH_HEADLESS",
        "false"
    ).lower()
    == "true"
)


# ============================================================
# STATE FILE
# ============================================================

BASE_DIR = Path(__file__).resolve().parent

DATA_DIR = (
    BASE_DIR
    / "data"
)

STATE_FILE = (
    DATA_DIR
    / "processed_alerts.json"
)


# ============================================================
# GLOBAL
# ============================================================

running = True


# ============================================================
# CTRL+C HANDLER
# ============================================================

def stop_program(signum, frame):

    global running

    print()
    print()
    print(
        "[INFO] Stop signal diterima."
    )

    running = False


signal.signal(
    signal.SIGINT,
    stop_program
)

signal.signal(
    signal.SIGTERM,
    stop_program
)


# ============================================================
# VALIDATE CONFIG
# ============================================================

def validate_config():

    missing = []

    if not WAZUH_USERNAME:
        missing.append(
            "WAZUH_USERNAME"
        )

    if not WAZUH_PASSWORD:
        missing.append(
            "WAZUH_PASSWORD"
        )

    if missing:

        raise RuntimeError(
            "Environment variable belum tersedia: "
            + ", ".join(missing)
        )


# ============================================================
# LOAD STATE
# ============================================================

def load_processed_alerts():

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    if not STATE_FILE.exists():

        return {
            "processed_ids": []
        }

    try:

        with open(
            STATE_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(file)

        if not isinstance(
            data.get("processed_ids"),
            list
        ):

            data["processed_ids"] = []

        return data

    except Exception as error:

        print(
            "[WARNING] Gagal membaca state:"
        )

        print(error)

        return {
            "processed_ids": []
        }


# ============================================================
# SAVE STATE
# ============================================================

def save_processed_alerts(state):

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )

    temporary_file = (
        STATE_FILE.with_suffix(
            ".tmp"
        )
    )

    with open(
        temporary_file,
        "w",
        encoding="utf-8"
    ) as file:

        json.dump(
            state,
            file,
            indent=2,
            ensure_ascii=False
        )

    temporary_file.replace(
        STATE_FILE
    )


# ============================================================
# LIMIT STATE SIZE
# ============================================================

def cleanup_state(
    state,
    max_ids=10000
):

    ids = state.get(
        "processed_ids",
        []
    )

    if len(ids) > max_ids:

        state["processed_ids"] = (
            ids[-max_ids:]
        )


# ============================================================
# LOGIN DASHBOARD
# ============================================================

def login_dashboard(page):

    print()
    print("=" * 70)
    print("LOGIN WAZUH CLOUD")
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
        "[AUTH] Menunggu form..."
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


    username.fill(
        WAZUH_USERNAME
    )

    password.fill(
        WAZUH_PASSWORD
    )


    button = page.locator(
        'button[type="submit"]'
    )


    if button.count() > 0:

        button.click()

    else:

        password.press(
            "Enter"
        )


    try:

        page.wait_for_url(
            lambda url:
                "/app/login"
                not in url,
            timeout=60_000
        )

    except Exception:

        print(
            "[ERROR] Login gagal."
        )

        return False


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
# QUERY ALERTS
# ============================================================

def query_alerts(context):

    url = (
        f"{WAZUH_URL}"
        "/internal/search/opensearch"
    )


    body = {

        "size":
            QUERY_LIMIT,

        "from":
            0,

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


        # Urutan terbaru dahulu.
        #
        # Timestamp digunakan untuk waktu,
        # _id digunakan sebagai tie-breaker.
        #
        # Ini penting karena beberapa alert
        # dapat mempunyai timestamp identik.

        "sort": [

            {
                "timestamp": {
                    "order": "desc",
                    "unmapped_type": "date"
                }
            },

            {
                "_id": {
                    "order": "desc"
                }
            }
        ],


        "query": {

            "bool": {

                "filter": [

                    {
                        "range": {

                            "timestamp": {

                                "gte":
                                    f"now-{QUERY_WINDOW_MINUTES}m",

                                "lte":
                                    "now"
                            }
                        }
                    }

                ]
            }
        }
    }


    payload = {

        "params": {

            "index":
                "wazuh-alerts",

            "body":
                body
        }
    }


    headers = {

        "Content-Type":
            "application/json",

        "osd-xsrf":
            "osd-fetch"
    }


    response = (
        context.request.post(
            url,
            headers=headers,
            data=payload,
            timeout=30_000
        )
    )


    if not response.ok:

        print(
            "[ERROR] Query OpenSearch:",
            response.status
        )

        try:

            print(
                response.text()[:2000]
            )

        except Exception:
            pass

        return []


    try:

        response_data = (
            response.json()
        )

    except Exception:

        print(
            "[ERROR] Response OpenSearch "
            "bukan JSON."
        )

        return []


    raw = response_data.get(
        "rawResponse",
        response_data
    )


    hits = (
        raw
        .get("hits", {})
        .get("hits", [])
    )


    return hits


# ============================================================
# UNIQUE ALERT ID
# ============================================================

def get_alert_unique_id(hit):

    index_name = hit.get(
        "_index",
        "unknown-index"
    )

    document_id = hit.get(
        "_id"
    )


    # Pilihan utama:
    # _index + _id
    #
    # Karena OpenSearch document _id
    # mengidentifikasi document di index.

    if document_id:

        return (
            f"{index_name}:"
            f"{document_id}"
        )


    # Fallback jika _id anehnya tidak tersedia.

    source = hit.get(
        "_source",
        {}
    )

    timestamp = source.get(
        "timestamp",
        ""
    )

    rule_id = (
        source
        .get("rule", {})
        .get("id", "")
    )

    agent_id = (
        source
        .get("agent", {})
        .get("id", "")
    )

    full_log = source.get(
        "full_log",
        ""
    )


    return (
        f"{timestamp}|"
        f"{agent_id}|"
        f"{rule_id}|"
        f"{full_log}"
    )


# ============================================================
# NORMALIZE ALERT
# ============================================================

def normalize_alert(hit):

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


    return {

        "unique_id":
            get_alert_unique_id(
                hit
            ),

        "index":
            hit.get(
                "_index",
                "-"
            ),

        "document_id":
            hit.get(
                "_id",
                "-"
            ),

        "timestamp":
            source.get(
                "timestamp",
                "-"
            ),

        "agent_id":
            agent.get(
                "id",
                "-"
            ),

        "agent_name":
            agent.get(
                "name",
                "-"
            ),

        "agent_ip":
            agent.get(
                "ip",
                "-"
            ),

        "manager":
            manager.get(
                "name",
                "-"
            ),

        "rule_id":
            rule.get(
                "id",
                "-"
            ),

        "level":
            int(
                rule.get(
                    "level",
                    0
                )
                or 0
            ),

        "description":
            rule.get(
                "description",
                "-"
            ),

        "groups":
            rule.get(
                "groups",
                []
            ),

        "firedtimes":
            rule.get(
                "firedtimes",
                0
            ),

        "location":
            source.get(
                "location",
                "-"
            ),

        "decoder":
            decoder.get(
                "name",
                "-"
            ),

        "full_log":
            source.get(
                "full_log",
                "-"
            ),

        "data":
            source.get(
                "data",
                {}
            )
    }


# ============================================================
# PRINT ALERT
# ============================================================

def print_alert(alert):

    print()
    print("-" * 70)

    print(
        "NEW WAZUH ALERT"
    )

    print("-" * 70)

    print(
        "Timestamp   :",
        alert["timestamp"]
    )

    print(
        "Agent       :",
        alert["agent_name"]
    )

    print(
        "Agent ID    :",
        alert["agent_id"]
    )

    print(
        "Agent IP    :",
        alert["agent_ip"]
    )

    print(
        "Rule ID     :",
        alert["rule_id"]
    )

    print(
        "Level       :",
        alert["level"]
    )

    print(
        "Description :",
        alert["description"]
    )

    print(
        "Groups      :",
        alert["groups"]
    )

    print(
        "Location    :",
        alert["location"]
    )


    if (
        alert["full_log"]
        and alert["full_log"] != "-"
    ):

        print()
        print("Full log:")

        print(
            alert["full_log"][:1000]
        )


# ============================================================
# PROCESS NEW ALERT
# ============================================================

def process_alert(alert):

    """
    Untuk sekarang hanya print.

    Tahap berikutnya:
        level 1-5  -> Telegram
        level 6-15 -> Gemini -> Telegram
    """

    print_alert(
        alert
    )


# ============================================================
# FIRST RUN INITIALIZATION
# ============================================================

def initialize_existing_alerts(
    context,
    state
):

    """
    Saat program pertama kali dijalankan,
    alert yang SUDAH ADA tidak langsung dianggap
    sebagai alert baru.

    Tujuannya mencegah program mengirim seluruh
    history ke Telegram ketika bot pertama kali
    diaktifkan.
    """

    print()
    print(
        "[INIT] First-run initialization..."
    )


    hits = query_alerts(
        context
    )


    if not hits:

        print(
            "[INIT] Tidak ada alert existing."
        )

        return


    processed_ids = set(
        state.get(
            "processed_ids",
            []
        )
    )


    for hit in hits:

        unique_id = (
            get_alert_unique_id(
                hit
            )
        )

        processed_ids.add(
            unique_id
        )


    state["processed_ids"] = list(
        processed_ids
    )


    cleanup_state(
        state
    )


    save_processed_alerts(
        state
    )


    print(
        "[INIT]",
        len(hits),
        "alert existing ditandai "
        "sebagai sudah diproses."
    )

    print(
        "[INIT] Bot sekarang menunggu "
        "alert BARU."
    )


# ============================================================
# POLL
# ============================================================

def poll_once(
    context,
    state
):

    hits = query_alerts(
        context
    )


    if not hits:

        return 0


    processed = set(
        state.get(
            "processed_ids",
            []
        )
    )


    new_alerts = []


    for hit in hits:

        unique_id = (
            get_alert_unique_id(
                hit
            )
        )


        if unique_id in processed:

            continue


        alert = normalize_alert(
            hit
        )


        new_alerts.append(
            alert
        )


    # ========================================================
    # QUERY menghasilkan newest -> oldest.
    #
    # Saat mengirim notifikasi lebih natural kalau:
    #
    # OLD -> NEW
    #
    # sehingga kita balik.
    # ========================================================

    new_alerts.reverse()


    for alert in new_alerts:

        try:

            process_alert(
                alert
            )


            # PENTING:
            #
            # Tandai sebagai processed hanya
            # SETELAH proses alert berhasil.
            #
            # Nanti ketika Telegram dipasang,
            # jika pengiriman Telegram gagal,
            # alert tidak akan hilang.

            processed.add(
                alert["unique_id"]
            )


        except Exception as error:

            print()
            print(
                "[ERROR] Gagal memproses alert:"
            )

            print(error)

            # Jangan mark processed.
            # Akan dicoba lagi pada poll berikutnya.


    state["processed_ids"] = list(
        processed
    )


    cleanup_state(
        state
    )


    save_processed_alerts(
        state
    )


    return len(
        new_alerts
    )


# ============================================================
# MONITOR LOOP
# ============================================================

def run_monitor(context):

    print()
    print("=" * 70)
    print("WAZUH REALTIME ALERT MONITOR")
    print("=" * 70)

    print(
        "Polling interval :",
        POLL_INTERVAL,
        "detik"
    )

    print(
        "Query window     :",
        QUERY_WINDOW_MINUTES,
        "menit"
    )

    print(
        "Query limit      :",
        QUERY_LIMIT
    )

    print(
        "State file       :",
        STATE_FILE
    )


    state = (
        load_processed_alerts()
    )


    first_run = (
        len(
            state.get(
                "processed_ids",
                []
            )
        )
        == 0
    )


    if first_run:

        initialize_existing_alerts(
            context,
            state
        )


    print()
    print(
        "[MONITOR] Aktif."
    )

    print(
        "[MONITOR] Tekan CTRL+C "
        "untuk berhenti."
    )


    while running:

        try:

            now = datetime.now().strftime(
                "%Y-%m-%d %H:%M:%S"
            )

            print()
            print(
                f"[{now}] Checking alerts..."
            )


            count = poll_once(
                context,
                state
            )


            if count == 0:

                print(
                    "[INFO] Tidak ada alert baru."
                )

            else:

                print()
                print(
                    f"[INFO] {count} alert baru "
                    "berhasil diproses."
                )


        except Exception as error:

            print()
            print(
                "[ERROR] Polling gagal:"
            )

            print(
                type(error).__name__,
                ":",
                error
            )


        # ================================================
        # Sleep dibuat per 1 detik agar CTRL+C
        # lebih responsif.
        # ================================================

        for _ in range(
            POLL_INTERVAL
        ):

            if not running:
                break

            time.sleep(1)


# ============================================================
# MAIN
# ============================================================

def main():

    validate_config()


    print()
    print("=" * 70)
    print("WAZUH REALTIME POLLER")
    print("=" * 70)

    print(
        "Wazuh:",
        WAZUH_URL
    )

    print(
        "Username:",
        WAZUH_USERNAME
    )

    print(
        "Password: ********"
    )


    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=HEADLESS
        )


        context = browser.new_context(
            ignore_https_errors=True
        )


        page = context.new_page()


        try:

            # =================================================
            # LOGIN
            # =================================================

            if not login_dashboard(
                page
            ):

                print(
                    "[STOP] Login gagal."
                )

                return


            # =================================================
            # MONITOR
            # =================================================

            run_monitor(
                context
            )


        finally:

            print()
            print(
                "[INFO] Menutup Chromium..."
            )

            browser.close()


# ============================================================
# RUN
# ============================================================

if __name__ == "__main__":
    main()