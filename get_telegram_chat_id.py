import os
import json
import requests

from dotenv import load_dotenv


# ============================================================
# LOAD ENV
# ============================================================

load_dotenv()


BOT_TOKEN = os.getenv(
    "TELEGRAM_BOT_TOKEN"
)


# ============================================================
# VALIDASI
# ============================================================

def validate_config():

    if not BOT_TOKEN:

        raise RuntimeError(
            "TELEGRAM_BOT_TOKEN belum tersedia di .env"
        )


# ============================================================
# GET UPDATES
# ============================================================

def get_updates():

    url = (
        f"https://api.telegram.org/"
        f"bot{BOT_TOKEN}/getUpdates"
    )

    print()
    print("=" * 60)
    print("TELEGRAM GET UPDATES")
    print("=" * 60)

    print(
        "Menghubungi Telegram Bot API..."
    )


    try:

        response = requests.get(
            url,
            timeout=20
        )

    except requests.RequestException as error:

        print(
            "[ERROR] Gagal terhubung ke Telegram:"
        )

        print(error)

        return None


    print(
        "HTTP Status:",
        response.status_code
    )


    try:

        data = response.json()

    except Exception:

        print(
            "[ERROR] Telegram tidak memberikan JSON."
        )

        print(
            response.text[:2000]
        )

        return None


    if not response.ok:

        print(
            "[ERROR] Telegram API error:"
        )

        print(
            json.dumps(
                data,
                indent=4,
                ensure_ascii=False
            )
        )

        return None


    return data


# ============================================================
# FIND CHAT
# ============================================================

def find_chat_ids(data):

    results = data.get(
        "result",
        []
    )


    if not results:

        print()
        print(
            "Tidak ada update ditemukan."
        )

        print()
        print(
            "Pastikan Anda sudah membuka bot "
            "dan mengirim /start."
        )

        return


    print()
    print("=" * 60)
    print("CHAT DITEMUKAN")
    print("=" * 60)


    found = set()


    for update in results:

        # Update biasanya memiliki:
        # message / edited_message / channel_post / dll.

        message = (
            update.get("message")
            or update.get("edited_message")
            or update.get("channel_post")
            or update.get("edited_channel_post")
        )


        if not message:
            continue


        chat = message.get(
            "chat",
            {}
        )


        chat_id = chat.get(
            "id"
        )


        if chat_id is None:
            continue


        if chat_id in found:
            continue


        found.add(
            chat_id
        )


        print()
        print("-" * 60)

        print(
            "CHAT ID   :",
            chat_id
        )

        print(
            "TYPE      :",
            chat.get(
                "type",
                "-"
            )
        )

        print(
            "USERNAME  :",
            chat.get(
                "username",
                "-"
            )
        )

        print(
            "FIRST NAME:",
            chat.get(
                "first_name",
                "-"
            )
        )

        print(
            "LAST NAME :",
            chat.get(
                "last_name",
                "-"
            )
        )

        print(
            "TITLE     :",
            chat.get(
                "title",
                "-"
            )
        )


    if not found:

        print()
        print(
            "Update ada, tetapi chat ID "
            "belum ditemukan."
        )


# ============================================================
# MAIN
# ============================================================

def main():

    validate_config()

    data = get_updates()

    if data is None:
        return


    find_chat_ids(
        data
    )


if __name__ == "__main__":
    main()