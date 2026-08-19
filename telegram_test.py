import os
import json
import requests

from dotenv import load_dotenv


load_dotenv()


BOT_TOKEN = os.getenv(
    "TELEGRAM_BOT_TOKEN"
)

CHAT_ID = os.getenv(
    "TELEGRAM_CHAT_ID"
)


# ============================================================
# VALIDATE
# ============================================================

def validate_config():

    missing = []

    if not BOT_TOKEN:
        missing.append(
            "TELEGRAM_BOT_TOKEN"
        )

    if not CHAT_ID:
        missing.append(
            "TELEGRAM_CHAT_ID"
        )


    if missing:

        raise RuntimeError(
            "Environment variable belum tersedia: "
            + ", ".join(missing)
        )


# ============================================================
# TEST BOT TOKEN
# ============================================================

def get_bot_info():

    url = (
        f"https://api.telegram.org/"
        f"bot{BOT_TOKEN}/getMe"
    )


    print()
    print("=" * 60)
    print("[1] TEST BOT TOKEN")
    print("=" * 60)


    response = requests.get(
        url,
        timeout=20
    )


    print(
        "HTTP:",
        response.status_code
    )


    data = response.json()


    if not response.ok:

        print(
            json.dumps(
                data,
                indent=4,
                ensure_ascii=False
            )
        )

        return False


    if not data.get("ok"):

        print(
            "[FAILED] Token tidak valid."
        )

        return False


    bot = data.get(
        "result",
        {}
    )


    print(
        "[SUCCESS] Bot ditemukan."
    )

    print(
        "Bot ID   :",
        bot.get("id")
    )

    print(
        "Name     :",
        bot.get("first_name")
    )

    print(
        "Username : @"
        + str(
            bot.get(
                "username",
                "-"
            )
        )
    )


    return True


# ============================================================
# SEND MESSAGE
# ============================================================

def send_test_message():

    url = (
        f"https://api.telegram.org/"
        f"bot{BOT_TOKEN}/sendMessage"
    )


    message = """
🛡 WAZUH SECURITY MONITOR

✅ Telegram Bot berhasil terhubung.

Status:
Wazuh → Python → Telegram siap digunakan.

Mode AI:
• Level 0–6  : Tanpa Gemini
• Level 7–15 : Gemini

Ini adalah pesan pengujian.
""".strip()


    payload = {

        "chat_id":
            CHAT_ID,

        "text":
            message
    }


    print()
    print("=" * 60)
    print("[2] SEND TEST MESSAGE")
    print("=" * 60)


    response = requests.post(
        url,
        json=payload,
        timeout=20
    )


    print(
        "HTTP:",
        response.status_code
    )


    try:

        data = response.json()

    except Exception:

        print(
            "[ERROR] Response bukan JSON."
        )

        print(
            response.text[:2000]
        )

        return False


    if not response.ok:

        print(
            "[FAILED] Telegram sendMessage gagal."
        )

        print(
            json.dumps(
                data,
                indent=4,
                ensure_ascii=False
            )
        )

        return False


    if not data.get("ok"):

        print(
            "[FAILED] Telegram API "
            "mengembalikan ok=false."
        )

        print(
            json.dumps(
                data,
                indent=4,
                ensure_ascii=False
            )
        )

        return False


    result = data.get(
        "result",
        {}
    )


    print(
        "[SUCCESS] Pesan berhasil dikirim."
    )

    print(
        "Message ID:",
        result.get(
            "message_id"
        )
    )


    return True


# ============================================================
# MAIN
# ============================================================

def main():

    validate_config()


    print()
    print("=" * 60)
    print("TELEGRAM BOT CONNECTION TEST")
    print("=" * 60)


    if not get_bot_info():

        print()
        print(
            "[STOP] Periksa BOT_TOKEN."
        )

        return


    if not send_test_message():

        print()
        print(
            "[STOP] Periksa CHAT_ID."
        )

        return


    print()
    print("=" * 60)
    print("SEMUA TEST TELEGRAM BERHASIL")
    print("=" * 60)

    print(
        "✓ Bot token valid"
    )

    print(
        "✓ Chat ID valid"
    )

    print(
        "✓ sendMessage berhasil"
    )


if __name__ == "__main__":
    main()