import os
import html
import requests

from dotenv import load_dotenv


# ============================================================
# ENV
# ============================================================

load_dotenv()


TELEGRAM_BOT_TOKEN = os.getenv(
    "TELEGRAM_BOT_TOKEN"
)

TELEGRAM_CHAT_ID = os.getenv(
    "TELEGRAM_CHAT_ID"
)


# ============================================================
# CONFIG
# ============================================================

def validate_telegram_config():

    missing = []


    if not TELEGRAM_BOT_TOKEN:

        missing.append(
            "TELEGRAM_BOT_TOKEN"
        )


    if not TELEGRAM_CHAT_ID:

        missing.append(
            "TELEGRAM_CHAT_ID"
        )


    if missing:

        raise RuntimeError(
            "Telegram configuration belum tersedia: "
            + ", ".join(missing)
        )


# ============================================================
# HELPERS
# ============================================================

def clip(
    value,
    max_length
):

    if value is None:

        return "-"


    text = str(
        value
    )


    if len(text) <= max_length:

        return text


    return (
        text[:max_length]
        + "\n...[dipotong]"
    )


def safe(value):

    if value is None:

        return "-"


    if isinstance(
        value,
        list
    ):

        value = ", ".join(
            str(item)
            for item in value
        )


    return html.escape(
        str(value)
    )


# ============================================================
# SEVERITY DISPLAY
#
# Ini hanya label UI Telegram.
# Routing AI tetap murni:
#
# 0-6  = Direct
# 7-15 = Gemini
# ============================================================

def get_severity(level):

    if level <= 3:

        return (
            "🟢",
            "INFORMATION"
        )


    if level <= 6:

        return (
            "🟡",
            "ATTENTION"
        )


    if level <= 9:

        return (
            "🟠",
            "HIGH"
        )


    if level <= 12:

        return (
            "🔴",
            "VERY HIGH"
        )


    return (
        "🚨",
        "CRITICAL"
    )


# ============================================================
# TELEGRAM REQUEST
# ============================================================

def send_telegram_message(
    message
):

    validate_telegram_config()


    # Jangan print URL ini karena berisi BOT TOKEN.
    url = (
        "https://api.telegram.org/"
        f"bot{TELEGRAM_BOT_TOKEN}"
        "/sendMessage"
    )


    payload = {

        "chat_id":
            TELEGRAM_CHAT_ID,

        "text":
            message,

        "parse_mode":
            "HTML",

        "disable_web_page_preview":
            True
    }


    try:

        response = requests.post(
            url,
            json=payload,
            timeout=20
        )


    except requests.RequestException as error:

        raise RuntimeError(
            "Gagal terhubung ke Telegram: "
            + str(error)
        )


    try:

        data = response.json()


    except Exception:

        raise RuntimeError(
            "Telegram memberikan response "
            "yang bukan JSON."
        )


    if not response.ok:

        description = data.get(
            "description",
            "Unknown Telegram error"
        )


        raise RuntimeError(
            f"Telegram HTTP "
            f"{response.status_code}: "
            f"{description}"
        )


    if not data.get(
        "ok",
        False
    ):

        raise RuntimeError(
            "Telegram API mengembalikan "
            "ok=false."
        )


    return data


# ============================================================
# FORMAT GROUPS
# ============================================================

def format_groups(alert):

    groups = alert.get(
        "groups",
        []
    )


    if not groups:

        return "-"


    return ", ".join(
        str(group)
        for group in groups
    )


# ============================================================
# DIRECT FORMAT
# LEVEL 0 - 6
# ============================================================

def format_direct_alert(alert):

    level = int(
        alert.get(
            "level",
            0
        )
    )


    icon, severity = (
        get_severity(
            level
        )
    )


    description = clip(
        alert.get(
            "description",
            "-"
        ),
        500
    )


    full_log = clip(
        alert.get(
            "full_log",
            "-"
        ),
        900
    )


    groups = clip(
        format_groups(
            alert
        ),
        400
    )


    return f"""
{icon} <b>WAZUH SECURITY ALERT</b>

<b>Severity:</b> {safe(severity)}
<b>Wazuh Level:</b> {safe(level)}

🖥 <b>Agent</b>
Name: <code>{safe(alert.get("agent_name"))}</code>
ID: <code>{safe(alert.get("agent_id"))}</code>
IP: <code>{safe(alert.get("agent_ip"))}</code>

📌 <b>Detection</b>
Rule ID: <code>{safe(alert.get("rule_id"))}</code>
{safe(description)}

📂 <b>Groups</b>
{safe(groups)}

📍 <b>Location</b>
{safe(alert.get("location"))}

🕒 <b>Timestamp</b>
{safe(alert.get("timestamp"))}

📄 <b>Event</b>
<pre>{safe(full_log)}</pre>

⚙️ <b>Processing</b>
Direct processing — Gemini tidak digunakan.
""".strip()


# ============================================================
# FORMAT LIST
# ============================================================

def format_bullet_list(
    values,
    max_items=4,
    max_length=180
):

    if not isinstance(
        values,
        list
    ):

        return "• -"


    result = []


    for value in values[
        :max_items
    ]:

        result.append(
            "• "
            + safe(
                clip(
                    value,
                    max_length
                )
            )
        )


    return "\n".join(
        result
    ) or "• -"


def format_numbered_list(
    values,
    max_items=5,
    max_length=190
):

    if not isinstance(
        values,
        list
    ):

        return "1. -"


    result = []


    for number, value in enumerate(
        values[:max_items],
        start=1
    ):

        result.append(
            f"{number}. "
            + safe(
                clip(
                    value,
                    max_length
                )
            )
        )


    return "\n".join(
        result
    ) or "1. -"


# ============================================================
# AI FORMAT
# LEVEL 7 - 15
# ============================================================

def format_ai_alert(
    alert,
    analysis,
    model,
    cached
):

    level = int(
        alert.get(
            "level",
            0
        )
    )


    icon, severity = (
        get_severity(
            level
        )
    )


    ai_source = (
        "CACHE"
        if cached
        else "LIVE GEMINI"
    )


    raw_event = clip(
        alert.get(
            "full_log",
            "-"
        ),
        550
    )


    summary = clip(
        analysis.get(
            "ringkasan",
            "-"
        ),
        350
    )


    impact = clip(
        analysis.get(
            "dampak",
            "-"
        ),
        320
    )


    attention_reason = clip(
        analysis.get(
            "alasan_tingkat_perhatian",
            "-"
        ),
        260
    )


    conclusion = clip(
        analysis.get(
            "kesimpulan",
            "-"
        ),
        300
    )


    causes = format_bullet_list(

        analysis.get(
            "kemungkinan_penyebab",
            []
        ),

        max_items=4,

        max_length=180
    )


    actions = format_numbered_list(

        analysis.get(
            "tindakan",
            []
        ),

        max_items=5,

        max_length=190
    )


    return f"""
{icon} <b>WAZUH AI SECURITY ALERT</b>

<b>Severity:</b> {safe(severity)}
<b>Wazuh Level:</b> {safe(level)}

🖥 <b>Agent</b>
Name: <code>{safe(alert.get("agent_name"))}</code>
ID: <code>{safe(alert.get("agent_id"))}</code>
IP: <code>{safe(alert.get("agent_ip"))}</code>

📌 <b>Detection</b>
Rule ID: <code>{safe(alert.get("rule_id"))}</code>
{safe(clip(alert.get("description"), 400))}

📍 <b>Location</b>
{safe(alert.get("location"))}

🕒 <b>Timestamp</b>
{safe(alert.get("timestamp"))}

📄 <b>Wazuh Event</b>
<pre>{safe(raw_event)}</pre>

🤖 <b>AI ANALYSIS</b>

<b>Ringkasan</b>
{safe(summary)}

<b>Kemungkinan Penyebab</b>
{causes}

<b>Dampak</b>
{safe(impact)}

<b>Tingkat Perhatian</b>
{safe(analysis.get("tingkat_perhatian", "-"))}
{safe(attention_reason)}

<b>Tindakan Yang Disarankan</b>
{actions}

<b>Kesimpulan</b>
{safe(conclusion)}

────────────────────
Model: <code>{safe(model)}</code>
AI Source: <code>{safe(ai_source)}</code>
""".strip()


# ============================================================
# FALLBACK FORMAT
# ============================================================

def format_ai_fallback_alert(
    alert,
    reason
):

    level = int(
        alert.get(
            "level",
            0
        )
    )


    icon, severity = (
        get_severity(
            level
        )
    )


    full_log = clip(
        alert.get(
            "full_log",
            "-"
        ),
        1100
    )


    reason = clip(
        reason,
        400
    )


    return f"""
{icon} <b>WAZUH HIGH-LEVEL ALERT</b>

⚠️ <b>AI ANALYSIS UNAVAILABLE</b>

<b>Severity:</b> {safe(severity)}
<b>Wazuh Level:</b> {safe(level)}

🖥 <b>Agent</b>
Name: <code>{safe(alert.get("agent_name"))}</code>
ID: <code>{safe(alert.get("agent_id"))}</code>
IP: <code>{safe(alert.get("agent_ip"))}</code>

📌 <b>Detection</b>
Rule ID: <code>{safe(alert.get("rule_id"))}</code>
{safe(clip(alert.get("description"), 450))}

📍 <b>Location</b>
{safe(alert.get("location"))}

🕒 <b>Timestamp</b>
{safe(alert.get("timestamp"))}

📄 <b>Raw Wazuh Event</b>
<pre>{safe(full_log)}</pre>

⚠️ <b>Gemini Status</b>
Analisis AI gagal atau tidak tersedia.

<b>Reason:</b>
{safe(reason)}

Alert asli Wazuh tetap dikirim agar event keamanan
tidak hilang.
""".strip()


# ============================================================
# SEND DIRECT
# ============================================================

def send_direct_wazuh_alert(
    alert
):

    message = (
        format_direct_alert(
            alert
        )
    )


    result = (
        send_telegram_message(
            message
        )
    )


    return {

        "success":
            True,

        "route":
            "telegram-direct",

        "telegram":
            result
    }


# ============================================================
# SEND AI
# ============================================================

def send_ai_wazuh_alert(
    alert,
    analysis,
    model,
    cached=False
):

    message = (
        format_ai_alert(

            alert,

            analysis,

            model,

            cached
        )
    )


    result = (
        send_telegram_message(
            message
        )
    )


    return {

        "success":
            True,

        "route":
            (
                "gemini-cache"
                if cached
                else "gemini-live"
            ),

        "telegram":
            result
    }


# ============================================================
# SEND FALLBACK
# ============================================================

def send_ai_fallback_alert(
    alert,
    reason
):

    message = (
        format_ai_fallback_alert(
            alert,
            reason
        )
    )


    result = (
        send_telegram_message(
            message
        )
    )


    return {

        "success":
            True,

        "route":
            "gemini-fallback",

        "telegram":
            result
    }