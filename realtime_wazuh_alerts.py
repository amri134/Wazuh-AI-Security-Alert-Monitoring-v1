import os
import json
import time
import signal
import hashlib

from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

from dotenv import load_dotenv
from playwright.sync_api import sync_playwright

from services.telegram_service import (
    validate_telegram_config,
    send_direct_wazuh_alert,
    send_ai_wazuh_alert,
    send_ai_fallback_alert
)

from services.gemini_service import (
    create_gemini_client,
    analyze_wazuh_alert
)


# ============================================================
# ENV
# ============================================================

load_dotenv()


WAZUH_URL = os.getenv(
    "WAZUH_URL",
    ""
).rstrip("/")


WAZUH_USERNAME = os.getenv(
    "WAZUH_USERNAME"
)


WAZUH_PASSWORD = os.getenv(
    "WAZUH_PASSWORD"
)


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
    )
    .strip()
    .lower()
    == "true"
)


# ============================================================
# PATH
# ============================================================

BASE_DIR = (
    Path(__file__)
    .resolve()
    .parent
)


DATA_DIR = (
    BASE_DIR
    / "data"
)


# ============================================================
# STATE PER WAZUH HOST
# ============================================================

parsed_host = (
    urlparse(
        WAZUH_URL
    ).hostname
    or "wazuh"
)


safe_host = (
    parsed_host
    .replace(
        ".",
        "_"
    )
    .replace(
        ":",
        "_"
    )
)


STATE_FILE = (
    DATA_DIR
    / (
        "processed_alerts_"
        + safe_host
        + ".json"
    )
)


# ============================================================
# RUN FLAG
# ============================================================

running = True


# ============================================================
# SIGNAL
# ============================================================

def stop_program(
    signum,
    frame
):

    global running


    print()
    print(
        "[INFO] Stop signal diterima."
    )


    running = False


signal.signal(
    signal.SIGINT,
    stop_program
)


try:

    signal.signal(
        signal.SIGTERM,
        stop_program
    )

except Exception:

    pass


# ============================================================
# CONFIG
# ============================================================

def validate_config():

    missing = []


    if not WAZUH_URL:

        missing.append(
            "WAZUH_URL"
        )


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


    validate_telegram_config()


# ============================================================
# LOAD STATE
# ============================================================

def load_state():

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    if not STATE_FILE.exists():

        return {

            "initialized":
                False,

            "processed_ids":
                []
        }


    try:

        with open(
            STATE_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(
                file
            )


        if not isinstance(
            data,
            dict
        ):

            raise ValueError(
                "State bukan JSON object."
            )


        if not isinstance(
            data.get(
                "processed_ids"
            ),
            list
        ):

            data[
                "processed_ids"
            ] = []


        if "initialized" not in data:

            data[
                "initialized"
            ] = True


        return data


    except Exception as error:

        print(
            "[WARNING] State file gagal dibaca:"
        )

        print(
            error
        )


        return {

            "initialized":
                False,

            "processed_ids":
                []
        }


# ============================================================
# SAVE STATE ATOMIC
# ============================================================

def save_state(state):

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    temporary_file = (
        STATE_FILE
        .with_suffix(
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
# CLEANUP STATE
# ============================================================

def cleanup_state(
    state,
    max_ids=10000
):

    processed_ids = state.get(
        "processed_ids",
        []
    )


    if len(
        processed_ids
    ) > max_ids:

        state[
            "processed_ids"
        ] = (
            processed_ids[
                -max_ids:
            ]
        )


# ============================================================
# LOGIN
# ============================================================

def login_dashboard(page):

    print()
    print("=" * 70)
    print("LOGIN WAZUH CLOUD")
    print("=" * 70)


    login_url = (
        f"{WAZUH_URL}/app/login"
    )


    print(
        "URL:",
        login_url
    )


    page.goto(
        login_url,
        wait_until=
            "domcontentloaded",
        timeout=
            60_000
    )


    username_input = page.locator(
        'input[placeholder="Username"]'
    )


    password_input = page.locator(
        'input[placeholder="Password"]'
    )


    print(
        "[AUTH] Menunggu form..."
    )


    try:

        username_input.wait_for(
            state="visible",
            timeout=60_000
        )


        password_input.wait_for(
            state="visible",
            timeout=60_000
        )


    except Exception:

        print(
            "[ERROR] Form login tidak ditemukan."
        )

        return False


    username_input.fill(
        WAZUH_USERNAME
    )


    password_input.fill(
        WAZUH_PASSWORD
    )


    submit_button = (
        page.locator(
            'button[type="submit"]'
        )
    )


    if submit_button.count() > 0:

        submit_button.click()

    else:

        password_input.press(
            "Enter"
        )


    try:

        page.wait_for_url(

            lambda url:
                "/app/login"
                not in url,

            timeout=
                60_000
        )


    except Exception:

        print(
            "[ERROR] Login Wazuh gagal."
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
#
# Endpoint ini mempertahankan mekanisme yang sudah berhasil
# pada Wazuh Cloud environment Anda.
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


        "sort": [

            {
                "timestamp": {

                    "order":
                        "desc",

                    "unmapped_type":
                        "date"
                }
            }

        ],


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

                "must":
                    [],

                "filter": [

                    {
                        "range": {

                            "timestamp": {

                                "gte":
                                    (
                                        "now-"
                                        + str(
                                            QUERY_WINDOW_MINUTES
                                        )
                                        + "m"
                                    ),

                                "lte":
                                    "now"
                            }
                        }
                    }

                ],

                "should":
                    [],

                "must_not":
                    []
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

            headers=
                headers,

            data=
                payload,

            timeout=
                30_000
        )
    )


    if not response.ok:

        raise RuntimeError(
            "Wazuh alert query gagal. "
            f"HTTP {response.status}"
        )


    try:

        result = (
            response.json()
        )


    except Exception:

        raise RuntimeError(
            "Wazuh memberikan response non-JSON."
        )


    raw_response = (
        result.get(
            "rawResponse",
            result
        )
    )


    hits = (

        raw_response
        .get(
            "hits",
            {}
        )
        .get(
            "hits",
            []
        )
    )


    if not isinstance(
        hits,
        list
    ):

        return []


    return hits


# ============================================================
# UNIQUE ID
# ============================================================

def get_alert_unique_id(hit):

    index_name = hit.get(
        "_index",
        "unknown-index"
    )


    document_id = hit.get(
        "_id"
    )


    # ========================================================
    # PRIMARY
    # ========================================================

    if document_id:

        return (
            f"{index_name}:"
            f"{document_id}"
        )


    # ========================================================
    # FALLBACK
    # ========================================================

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


    raw_identity = "|".join(
        [

            str(
                source.get(
                    "timestamp",
                    ""
                )
            ),

            str(
                agent.get(
                    "id",
                    ""
                )
            ),

            str(
                rule.get(
                    "id",
                    ""
                )
            ),

            str(
                source.get(
                    "full_log",
                    ""
                )
            )
        ]
    )


    digest = hashlib.sha256(
        raw_identity.encode(
            "utf-8"
        )
    ).hexdigest()


    return (
        "fallback:"
        + digest
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


    try:

        level = int(
            rule.get(
                "level",
                0
            )
            or 0
        )


    except Exception:

        level = 0


    groups = rule.get(
        "groups",
        []
    )


    if not isinstance(
        groups,
        list
    ):

        groups = [
            str(
                groups
            )
        ]


    data = source.get(
        "data",
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
            level,

        "description":
            rule.get(
                "description",
                "-"
            ),

        "groups":
            groups,

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
            data
    }


# ============================================================
# TERMINAL OUTPUT
# ============================================================

def print_alert(alert):

    print()
    print("-" * 70)
    print("NEW WAZUH ALERT")
    print("-" * 70)


    print(
        "Timestamp   :",
        alert[
            "timestamp"
        ]
    )


    print(
        "Agent       :",
        alert[
            "agent_name"
        ]
    )


    print(
        "Agent ID    :",
        alert[
            "agent_id"
        ]
    )


    print(
        "Agent IP    :",
        alert[
            "agent_ip"
        ]
    )


    print(
        "Rule ID     :",
        alert[
            "rule_id"
        ]
    )


    print(
        "Level       :",
        alert[
            "level"
        ]
    )


    print(
        "Description :",
        alert[
            "description"
        ]
    )


    print(
        "Groups      :",
        alert[
            "groups"
        ]
    )


    print(
        "Location    :",
        alert[
            "location"
        ]
    )


    full_log = alert.get(
        "full_log",
        "-"
    )


    if (
        full_log
        and
        full_log != "-"
    ):

        print()

        print(
            "Full log:"
        )

        print(
            str(
                full_log
            )[:2000]
        )


# ============================================================
# PROCESS ALERT
# ============================================================

def process_alert(
    alert,
    gemini_client
):

    print_alert(
        alert
    )


    level = int(
        alert.get(
            "level",
            0
        )
    )


    # ========================================================
    # LEVEL 0 - 6
    # ========================================================

    if 0 <= level <= 6:

        print()
        print(
            "[ROUTER] Level 0-6"
        )

        print(
            "[ROUTER] Gemini tidak digunakan."
        )

        print(
            "[TELEGRAM] Mengirim alert..."
        )


        result = (
            send_direct_wazuh_alert(
                alert
            )
        )


        print(
            "[TELEGRAM] Berhasil."
        )


        print(
            "[ROUTER] Route:",
            result.get(
                "route"
            )
        )


        return True


    # ========================================================
    # LEVEL 7 - 15
    # ========================================================

    if 7 <= level <= 15:

        print()
        print(
            "[ROUTER] Level 7-15"
        )

        print(
            "[ROUTER] Gemini analysis diperlukan."
        )


        # ====================================================
        # GEMINI CLIENT TIDAK TERSEDIA
        # ====================================================

        if gemini_client is None:

            reason = (
                "Gemini client tidak tersedia "
                "pada saat startup."
            )


            print(
                "[GEMINI]",
                reason
            )


            print(
                "[FALLBACK] Mengirim alert asli..."
            )


            result = (
                send_ai_fallback_alert(
                    alert,
                    reason
                )
            )


            print(
                "[FALLBACK] Telegram berhasil."
            )


            print(
                "[ROUTER] Route:",
                result.get(
                    "route"
                )
            )


            return True


        # ====================================================
        # GEMINI ANALYSIS
        # ====================================================

        try:

            ai_result = (
                analyze_wazuh_alert(

                    gemini_client,

                    alert
                )
            )


        except Exception as gemini_error:

            # =================================================
            # AI GAGAL
            #
            # Telegram fallback masih harus dikirim.
            # =================================================

            print()
            print(
                "[GEMINI] ANALYSIS FAILED"
            )


            print(
                type(
                    gemini_error
                ).__name__,
                ":",
                gemini_error
            )


            print(
                "[FALLBACK] Mengirim "
                "alert asli ke Telegram..."
            )


            result = (
                send_ai_fallback_alert(

                    alert,

                    str(
                        gemini_error
                    )
                )
            )


            print(
                "[FALLBACK] Telegram berhasil."
            )


            print(
                "[ROUTER] Route:",
                result.get(
                    "route"
                )
            )


            return True


        # ====================================================
        # AI SUKSES
        # ====================================================

        cached = ai_result.get(
            "cached",
            False
        )


        model = ai_result.get(
            "model",
            "Gemini"
        )


        analysis = ai_result[
            "analysis"
        ]


        print(
            "[GEMINI] Analysis berhasil."
        )


        print(
            "[GEMINI] Source:",
            (
                "CACHE"
                if cached
                else "LIVE"
            )
        )


        # ====================================================
        # TELEGRAM SEND
        #
        # Sengaja di luar try Gemini.
        #
        # Jika Telegram gagal, exception harus diteruskan
        # supaya event TIDAK ditandai processed.
        # ====================================================

        print(
            "[TELEGRAM] Mengirim AI alert..."
        )


        result = (
            send_ai_wazuh_alert(

                alert,

                analysis,

                model,

                cached
            )
        )


        print(
            "[TELEGRAM] AI alert berhasil."
        )


        print(
            "[ROUTER] Route:",
            result.get(
                "route"
            )
        )


        return True


    # ========================================================
    # INVALID LEVEL
    # ========================================================

    raise ValueError(
        "Wazuh level tidak valid: "
        + str(
            level
        )
    )


# ============================================================
# INITIALIZE EXISTING ALERTS
# ============================================================

def initialize_existing_alerts(
    context,
    state
):

    print()
    print(
        "[INIT] First-run initialization..."
    )


    hits = query_alerts(
        context
    )


    processed_ids = state.get(
        "processed_ids",
        []
    )


    processed_set = set(
        processed_ids
    )


    new_count = 0


    for hit in reversed(
        hits
    ):

        unique_id = (
            get_alert_unique_id(
                hit
            )
        )


        if unique_id in processed_set:

            continue


        processed_set.add(
            unique_id
        )


        processed_ids.append(
            unique_id
        )


        new_count += 1


    state[
        "processed_ids"
    ] = processed_ids


    state[
        "initialized"
    ] = True


    cleanup_state(
        state
    )


    save_state(
        state
    )


    print(
        "[INIT]",
        new_count,
        "alert existing ditandai "
        "sebagai sudah diproses."
    )


    print(
        "[INIT] Hanya alert baru "
        "yang akan dikirim."
    )


# ============================================================
# POLL ONCE
# ============================================================

def poll_once(
    context,
    state,
    gemini_client
):

    hits = query_alerts(
        context
    )


    if not hits:

        return 0


    processed_ids = state.get(
        "processed_ids",
        []
    )


    processed_set = set(
        processed_ids
    )


    new_alerts = []


    for hit in hits:

        unique_id = (
            get_alert_unique_id(
                hit
            )
        )


        if unique_id in processed_set:

            continue


        new_alerts.append(
            normalize_alert(
                hit
            )
        )


    # ========================================================
    # Query = newest first
    #
    # Telegram = oldest -> newest
    # ========================================================

    new_alerts.reverse()


    success_count = 0


    for alert in new_alerts:

        try:

            success = (
                process_alert(

                    alert,

                    gemini_client
                )
            )


            if not success:

                continue


            unique_id = alert[
                "unique_id"
            ]


            # =================================================
            # MARK PROCESSED ONLY AFTER TELEGRAM SUCCESS
            # =================================================

            if unique_id not in processed_set:

                processed_set.add(
                    unique_id
                )


                processed_ids.append(
                    unique_id
                )


            state[
                "processed_ids"
            ] = processed_ids


            cleanup_state(
                state
            )


            # cleanup dapat menghasilkan list baru
            processed_ids = state[
                "processed_ids"
            ]


            processed_set = set(
                processed_ids
            )


            save_state(
                state
            )


            success_count += 1


        except Exception as error:

            print()
            print("=" * 70)
            print("ALERT PROCESSING ERROR")
            print("=" * 70)


            print(
                "Agent:",
                alert.get(
                    "agent_name"
                )
            )


            print(
                "Rule:",
                alert.get(
                    "rule_id"
                )
            )


            print(
                "Level:",
                alert.get(
                    "level"
                )
            )


            print(
                "Error:",
                type(
                    error
                ).__name__,
                ":",
                error
            )


            print()
            print(
                "[RETRY] Alert BELUM "
                "ditandai processed."
            )


            print(
                "[RETRY] Event akan dicoba "
                "pada polling berikutnya."
            )


    return success_count


# ============================================================
# MONITOR
# ============================================================

def run_monitor(
    context,
    gemini_client
):

    print()
    print("=" * 70)
    print("WAZUH + GEMINI + TELEGRAM REALTIME MONITOR")
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


    print()
    print(
        "Routing:"
    )


    print(
        "  Level 0-6  -> Telegram langsung"
    )


    print(
        "  Level 7-15 -> Cache -> Gemini -> Telegram"
    )


    print(
        "  Gemini gagal -> Telegram fallback"
    )


    state = (
        load_state()
    )


    if not state.get(
        "initialized",
        False
    ):

        initialize_existing_alerts(
            context,
            state
        )


    print()
    print(
        "[MONITOR] Aktif."
    )


    print(
        "[MONITOR] Menunggu alert baru..."
    )


    print(
        "[MONITOR] Tekan CTRL+C untuk berhenti."
    )


    while running:

        try:

            now = (
                datetime.now()
                .strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
            )


            print()
            print(
                f"[{now}] Checking alerts..."
            )


            count = (
                poll_once(

                    context,

                    state,

                    gemini_client
                )
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
                type(
                    error
                ).__name__,
                ":",
                error
            )


        # ====================================================
        # RESPONSIVE SLEEP
        # ====================================================

        for _ in range(
            POLL_INTERVAL
        ):

            if not running:

                break


            time.sleep(
                1
            )


# ============================================================
# MAIN
# ============================================================

def main():

    validate_config()


    print()
    print("=" * 70)
    print("WAZUH AI SECURITY ALERT BOT")
    print("=" * 70)


    print(
        "Wazuh URL :",
        WAZUH_URL
    )


    print(
        "Username  :",
        WAZUH_USERNAME
    )


    print(
        "Password  : ********"
    )


    print(
        "Telegram  : configured"
    )


    print(
        "Gemini    : configured / fallback enabled"
    )


    gemini_client = None


    with sync_playwright() as playwright:

        browser = (
            playwright.chromium.launch(
                headless=HEADLESS
            )
        )


        context = (
            browser.new_context(
                ignore_https_errors=True
            )
        )


        page = (
            context.new_page()
        )


        try:

            # =================================================
            # WAZUH LOGIN
            # =================================================

            if not login_dashboard(
                page
            ):

                print(
                    "[STOP] Login Wazuh gagal."
                )

                return


            # =================================================
            # GEMINI INITIALIZATION
            #
            # Tidak melakukan API request di startup.
            #
            # Jadi tidak membuang quota hanya untuk healthcheck.
            # =================================================

            print()
            print(
                "[GEMINI] Initializing client..."
            )


            try:

                gemini_client = (
                    create_gemini_client()
                )


                print(
                    "[GEMINI] Client ready."
                )


            except Exception as error:

                print(
                    "[WARNING] Gemini client "
                    "tidak dapat dibuat."
                )


                print(
                    "[WARNING]",
                    type(
                        error
                    ).__name__,
                    ":",
                    error
                )


                print(
                    "[WARNING] Level 7-15 akan "
                    "menggunakan fallback Telegram."
                )


                gemini_client = None


            # =================================================
            # MONITOR
            # =================================================

            run_monitor(

                context,

                gemini_client
            )


        finally:

            # =================================================
            # CLOSE GEMINI
            # =================================================

            if gemini_client is not None:

                try:

                    gemini_client.close()

                except Exception:

                    pass


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