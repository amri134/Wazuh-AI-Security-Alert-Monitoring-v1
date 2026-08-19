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
WAZUH_HOST_ID = os.getenv("WAZUH_HOST_ID", "1")


# ============================================================
# VALIDASI
# ============================================================

def validate_config():

    if not WAZUH_USERNAME:
        raise RuntimeError(
            "WAZUH_USERNAME belum ada di .env"
        )

    if not WAZUH_PASSWORD:
        raise RuntimeError(
            "WAZUH_PASSWORD belum ada di .env"
        )


# ============================================================
# LOGIN DASHBOARD
# ============================================================

def login_dashboard(page):

    print()
    print("=" * 60)
    print("[1] LOGIN DASHBOARD")
    print("=" * 60)

    login_url = f"{WAZUH_URL}/app/login"

    print("URL:", login_url)

    page.goto(
        login_url,
        wait_until="domcontentloaded",
        timeout=60_000
    )

    print(
        "Current URL:",
        page.url
    )

    # ========================================================
    # TUNGGU INPUT USERNAME
    # ========================================================

    print()
    print(
        "[2] Menunggu form login..."
    )

    username = page.locator(
        'input[placeholder="Username"]'
    )

    password = page.locator(
        'input[placeholder="Password"]'
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

        print()
        print(
            "[ERROR] Form login tidak muncul "
            "setelah 60 detik."
        )

        print(
            "URL:",
            page.url
        )

        print(
            "Title:",
            page.title()
        )

        print(
            "Input count:",
            page.locator("input").count()
        )

        return False


    print(
        "[OK] Form login ditemukan."
    )


    # ========================================================
    # ISI CREDENTIAL
    # ========================================================

    print(
        "[3] Mengisi username..."
    )

    username.fill(
        WAZUH_USERNAME
    )

    print(
        "[4] Mengisi password..."
    )

    password.fill(
        WAZUH_PASSWORD
    )


    # ========================================================
    # SUBMIT
    # ========================================================

    button = page.locator(
        'button[type="submit"]'
    )

    try:

        button.wait_for(
            state="visible",
            timeout=10_000
        )

        print(
            "[5] Klik Login..."
        )

        button.click()

    except Exception:

        print(
            "[INFO] Tombol tidak ditemukan, "
            "menggunakan Enter."
        )

        password.press("Enter")


    # ========================================================
    # TUNGGU LOGIN SELESAI
    # ========================================================

    try:

        page.wait_for_url(
            lambda url:
                "/app/login" not in url,
            timeout=60_000
        )

    except Exception:

        print()
        print(
            "[ERROR] Login gagal."
        )

        print(
            "URL:",
            page.url
        )

        return False


    print()
    print("=" * 60)
    print(
        "[SUCCESS] LOGIN DASHBOARD BERHASIL"
    )
    print("=" * 60)

    print(
        "Dashboard:",
        page.url
    )

    return True


# ============================================================
# GET JWT
# ============================================================

def get_wazuh_jwt(context):

    print()
    print("=" * 60)
    print("[6] GET JWT WAZUH")
    print("=" * 60)

    response = context.request.post(

        f"{WAZUH_URL}/api/login",

        headers={
            "osd-xsrf": "kibana",
            "Content-Type": "application/json"
        },

        data={
            "idHost": WAZUH_HOST_ID,
            "force": False
        },

        timeout=30_000
    )

    print(
        "HTTP:",
        response.status
    )

    try:

        data = response.json()

    except Exception:

        print(
            "[ERROR] Response bukan JSON"
        )

        print(
            response.text()[:3000]
        )

        return None


    if not response.ok:

        print(
            "[ERROR] Gagal mendapatkan JWT"
        )

        print(
            json.dumps(
                data,
                indent=4
            )
        )

        return None


    token = data.get(
        "token"
    )

    if not token:

        print(
            "[ERROR] Field token tidak ada."
        )

        return None


    print()
    print(
        "[SUCCESS] JWT DIDAPAT"
    )

    print(
        "Token length:",
        len(token)
    )

    return token


# ============================================================
# TEST SERVER API VIA DASHBOARD
# ============================================================

def test_server_api(context):

    print()
    print("=" * 60)
    print("[7] TEST SERVER API")
    print("=" * 60)

    response = context.request.post(

        f"{WAZUH_URL}/api/request",

        headers={
            "osd-xsrf": "kibana",
            "Content-Type": "application/json"
        },

        data={
            "method": "GET",
            "path": "/agents/summary/status",
            "body": {},
            "id": WAZUH_HOST_ID
        },

        timeout=30_000
    )

    print(
        "HTTP:",
        response.status
    )


    try:

        data = response.json()

    except Exception:

        print(
            "[ERROR] Response bukan JSON"
        )

        print(
            response.text()[:3000]
        )

        return False


    print()
    print(
        json.dumps(
            data,
            indent=4,
            ensure_ascii=False
        )
    )


    if response.ok and data.get("error") == 0:

        print()
        print(
            "[SUCCESS] SERVER API BERHASIL"
        )

        return True


    print()
    print(
        "[FAILED] Server API gagal."
    )

    return False


# ============================================================
# MAIN
# ============================================================

def main():

    validate_config()

    print()
    print("=" * 60)
    print("WAZUH CLOUD TEST")
    print("=" * 60)

    print(
        "URL      :",
        WAZUH_URL
    )

    print(
        "Username :",
        WAZUH_USERNAME
    )

    print(
        "Password : ********"
    )

    print(
        "Host ID  :",
        WAZUH_HOST_ID
    )


    with sync_playwright() as p:

        browser = p.chromium.launch(
            headless=False
        )

        context = browser.new_context(
            ignore_https_errors=True
        )

        page = context.new_page()


        try:

            # ================================================
            # LOGIN
            # ================================================

            if not login_dashboard(page):

                print(
                    "\n[STOP] Login gagal."
                )

                return


            # Tunggu dashboard benar-benar siap
            page.wait_for_timeout(
                3000
            )


            # ================================================
            # JWT
            # ================================================

            token = get_wazuh_jwt(
                context
            )

            if not token:

                print(
                    "\n[STOP] JWT gagal."
                )

                return


            # ================================================
            # SERVER API
            # ================================================

            server_ok = test_server_api(
                context
            )


            # ================================================
            # FINAL
            # ================================================

            print()
            print("=" * 60)

            if server_ok:

                print(
                    "SEMUA TEST BERHASIL"
                )

                print("=" * 60)

                print(
                    "✓ Login Dashboard"
                )

                print(
                    "✓ Session Dashboard"
                )

                print(
                    "✓ JWT Wazuh"
                )

                print(
                    "✓ Server API"
                )

            else:

                print(
                    "LOGIN + JWT BERHASIL"
                )

                print(
                    "TETAPI SERVER API GAGAL"
                )

                print("=" * 60)


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