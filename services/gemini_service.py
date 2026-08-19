import os
import re
import json
import time
import random
import hashlib
from pathlib import Path

from dotenv import load_dotenv
from google import genai
from google.genai import types
from google.genai import errors


# ============================================================
# LOAD ENV
# ============================================================

load_dotenv()


GEMINI_API_KEY = os.getenv(
    "GEMINI_API_KEY"
)

GEMINI_MODEL = os.getenv(
    "GEMINI_MODEL",
    "gemini-3.6-flash"
)

GEMINI_MAX_OUTPUT_TOKENS = int(
    os.getenv(
        "GEMINI_MAX_OUTPUT_TOKENS",
        "2500"
    )
)

GEMINI_THINKING_LEVEL = os.getenv(
    "GEMINI_THINKING_LEVEL",
    "low"
).strip().lower()

GEMINI_RETRY_COUNT = int(
    os.getenv(
        "GEMINI_RETRY_COUNT",
        "2"
    )
)

GEMINI_CACHE_TTL_DAYS = int(
    os.getenv(
        "GEMINI_CACHE_TTL_DAYS",
        "30"
    )
)

GEMINI_CACHE_MAX_ENTRIES = int(
    os.getenv(
        "GEMINI_CACHE_MAX_ENTRIES",
        "1000"
    )
)


# ============================================================
# CONSTANT
# ============================================================

PROMPT_VERSION = "wazuh-security-v3"


# ============================================================
# PATH
# ============================================================

BASE_DIR = (
    Path(__file__)
    .resolve()
    .parent
    .parent
)

DATA_DIR = (
    BASE_DIR
    / "data"
)

CACHE_FILE = (
    DATA_DIR
    / "ai_cache.json"
)


# ============================================================
# STRUCTURED OUTPUT SCHEMA
# ============================================================

AI_RESPONSE_SCHEMA = {
    "type": "object",

    "properties": {

        "ringkasan": {
            "type": "string",
            "description": (
                "Ringkasan fakta keamanan "
                "yang benar-benar terdeteksi."
            )
        },

        "kemungkinan_penyebab": {
            "type": "array",
            "items": {
                "type": "string"
            },
            "minItems": 1,
            "maxItems": 4
        },

        "dampak": {
            "type": "string"
        },

        "tingkat_perhatian": {
            "type": "string",
            "enum": [
                "Rendah",
                "Sedang",
                "Tinggi",
                "Kritis"
            ]
        },

        "alasan_tingkat_perhatian": {
            "type": "string"
        },

        "tindakan": {
            "type": "array",
            "items": {
                "type": "string"
            },
            "minItems": 1,
            "maxItems": 5
        },

        "kesimpulan": {
            "type": "string"
        }
    },

    "required": [
        "ringkasan",
        "kemungkinan_penyebab",
        "dampak",
        "tingkat_perhatian",
        "alasan_tingkat_perhatian",
        "tindakan",
        "kesimpulan"
    ]
}


# ============================================================
# VALIDATE CONFIG
# ============================================================

def validate_gemini_config():

    if not GEMINI_API_KEY:

        raise RuntimeError(
            "GEMINI_API_KEY belum tersedia di .env"
        )

    if GEMINI_THINKING_LEVEL not in {
        "minimal",
        "low",
        "medium",
        "high"
    }:

        raise RuntimeError(
            "GEMINI_THINKING_LEVEL tidak valid: "
            f"{GEMINI_THINKING_LEVEL}"
        )


# ============================================================
# CLIENT
# ============================================================

def create_gemini_client():

    validate_gemini_config()

    return genai.Client(
        api_key=GEMINI_API_KEY
    )


# ============================================================
# SMALL HELPERS
# ============================================================

def clip_text(
    value,
    max_length
):

    if value is None:
        return ""

    text = str(value)

    if len(text) <= max_length:
        return text

    return (
        text[:max_length]
        + "\n...[dipotong]"
    )


def normalize_text(value):

    if value is None:
        return ""

    return " ".join(
        str(value)
        .strip()
        .lower()
        .split()
    )


# ============================================================
# EXTRACT TARGET
#
# Digunakan untuk membuat cache lebih aman.
#
# Contoh:
# File 'c:\wazuh-test\abc.txt' modified
# ============================================================

def extract_target(alert):

    full_log = str(
        alert.get(
            "full_log",
            ""
        )
    )


    # Wazuh FIM:
    # File 'c:\path\file.txt' modified
    match = re.search(
        r"File\s+'([^']+)'",
        full_log,
        re.IGNORECASE
    )

    if match:

        return normalize_text(
            match.group(1)
        )


    data = alert.get(
        "data",
        {}
    )


    possible_keys = {
        "file",
        "filename",
        "filepath",
        "file_path",
        "path",
        "targetfilename",
        "objectname"
    }


    def recursive_find(value):

        if isinstance(
            value,
            dict
        ):

            for key, child in value.items():

                normalized_key = (
                    str(key)
                    .replace(".", "")
                    .replace("_", "")
                    .lower()
                )

                if normalized_key in {
                    item
                    .replace("_", "")
                    .lower()
                    for item in possible_keys
                }:

                    if isinstance(
                        child,
                        (
                            str,
                            int,
                            float
                        )
                    ):

                        return normalize_text(
                            child
                        )


            for child in value.values():

                result = recursive_find(
                    child
                )

                if result:
                    return result


        elif isinstance(
            value,
            list
        ):

            for child in value:

                result = recursive_find(
                    child
                )

                if result:
                    return result


        return ""


    return recursive_find(
        data
    )


# ============================================================
# CACHE KEY
# ============================================================

def build_cache_key(alert):

    """
    Cache bukan berdasarkan document _id.

    Event Wazuh yang berbeda tetap boleh memakai
    analisis sebelumnya jika karakteristik keamanannya sama.

    Untuk event file, target/path juga dimasukkan agar
    analisis file A tidak sembarangan digunakan untuk file B.
    """

    signature = {

        "prompt_version":
            PROMPT_VERSION,

        "model":
            GEMINI_MODEL,

        "rule_id":
            str(
                alert.get(
                    "rule_id",
                    ""
                )
            ),

        "level":
            int(
                alert.get(
                    "level",
                    0
                )
            ),

        "description":
            normalize_text(
                alert.get(
                    "description",
                    ""
                )
            ),

        "location":
            normalize_text(
                alert.get(
                    "location",
                    ""
                )
            ),

        "decoder":
            normalize_text(
                alert.get(
                    "decoder",
                    ""
                )
            ),

        "groups":
            sorted(
                normalize_text(item)
                for item in alert.get(
                    "groups",
                    []
                )
            ),

        "target":
            extract_target(
                alert
            )
    }


    serialized = json.dumps(
        signature,
        ensure_ascii=False,
        sort_keys=True
    )


    return hashlib.sha256(
        serialized.encode(
            "utf-8"
        )
    ).hexdigest()


# ============================================================
# CACHE LOAD
# ============================================================

def load_cache():

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    if not CACHE_FILE.exists():

        return {}


    try:

        with open(
            CACHE_FILE,
            "r",
            encoding="utf-8"
        ) as file:

            data = json.load(
                file
            )


        if isinstance(
            data,
            dict
        ):

            return data


    except Exception as error:

        print(
            "[AI CACHE] Gagal membaca cache:",
            error
        )


    return {}


# ============================================================
# CACHE SAVE
# ============================================================

def save_cache(cache):

    DATA_DIR.mkdir(
        parents=True,
        exist_ok=True
    )


    temporary_file = (
        CACHE_FILE
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
            cache,
            file,
            indent=2,
            ensure_ascii=False
        )


    temporary_file.replace(
        CACHE_FILE
    )


# ============================================================
# CACHE CLEANUP
# ============================================================

def cleanup_cache(cache):

    now = time.time()

    ttl_seconds = (
        GEMINI_CACHE_TTL_DAYS
        * 24
        * 60
        * 60
    )


    valid_cache = {}


    for key, item in cache.items():

        created_at = float(
            item.get(
                "created_at",
                0
            )
            or 0
        )


        if (
            created_at
            and
            (
                now
                - created_at
            )
            <= ttl_seconds
        ):

            valid_cache[
                key
            ] = item


    # ========================================================
    # MAX ENTRIES
    # ========================================================

    if (
        len(valid_cache)
        >
        GEMINI_CACHE_MAX_ENTRIES
    ):

        sorted_items = sorted(

            valid_cache.items(),

            key=lambda pair:
                pair[1].get(
                    "created_at",
                    0
                )
        )


        sorted_items = (
            sorted_items[
                -GEMINI_CACHE_MAX_ENTRIES:
            ]
        )


        valid_cache = dict(
            sorted_items
        )


    return valid_cache


# ============================================================
# BUILD PROMPT
# ============================================================

def build_security_prompt(alert):

    groups = ", ".join(
        str(item)
        for item in alert.get(
            "groups",
            []
        )
    )


    data = alert.get(
        "data",
        {}
    )


    try:

        data_text = json.dumps(
            data,
            indent=2,
            ensure_ascii=False,
            default=str
        )

    except Exception:

        data_text = str(
            data
        )


    data_text = clip_text(
        data_text,
        5000
    )


    full_log = clip_text(
        alert.get(
            "full_log",
            "-"
        ),
        7000
    )


    return f"""
Anda adalah AI Security Analyst untuk alert Wazuh SIEM/XDR.

Tujuan Anda adalah membantu administrator memahami alert keamanan
dan menentukan tindakan selanjutnya.

ATURAN WAJIB:

- Analisis hanya berdasarkan evidence yang diberikan.
- Jangan mengarang fakta.
- Jangan menyatakan malware, ransomware, attacker, compromise,
  intrusion, persistence, credential theft, atau insiden keamanan
  telah benar-benar terjadi jika evidence tidak membuktikannya.
- Jika penyebab tidak diketahui dengan pasti, gunakan bahasa
  probabilistik seperti "kemungkinan", "dapat disebabkan oleh",
  atau "perlu verifikasi lebih lanjut".
- Bedakan fakta yang terdeteksi dengan dugaan.
- Jangan memberikan kepastian palsu.
- Berikan tindakan yang konkret dan realistis untuk administrator.
- Gunakan Bahasa Indonesia.
- Jangan gunakan Markdown table.
- Jangan menambahkan informasi yang tidak diperlukan.
- Jangan menyalin raw log secara utuh.
- Jangan mengklaim mengetahui user/proses pelaku jika alert tidak
  menyediakannya.
- Analisis dapat disimpan dalam cache dan digunakan lagi untuk
  event dengan rule dan target yang sama. Karena itu jangan
  mengandalkan timestamp sebagai bagian penting kesimpulan.

DATA ALERT WAZUH:

Timestamp:
{alert.get("timestamp", "-")}

Agent:
{alert.get("agent_name", "-")}

Agent ID:
{alert.get("agent_id", "-")}

Agent IP:
{alert.get("agent_ip", "-")}

Manager:
{alert.get("manager", "-")}

Rule ID:
{alert.get("rule_id", "-")}

Rule Level:
{alert.get("level", "-")}

Rule Description:
{alert.get("description", "-")}

Rule Groups:
{groups}

Location:
{alert.get("location", "-")}

Decoder:
{alert.get("decoder", "-")}

Full Log:
{full_log}

Additional Data:
{data_text}
""".strip()


# ============================================================
# VALIDATE AI RESULT
# ============================================================

def validate_analysis(
    analysis
):

    if not isinstance(
        analysis,
        dict
    ):

        raise RuntimeError(
            "Hasil Gemini bukan object JSON."
        )


    required = [
        "ringkasan",
        "kemungkinan_penyebab",
        "dampak",
        "tingkat_perhatian",
        "alasan_tingkat_perhatian",
        "tindakan",
        "kesimpulan"
    ]


    for key in required:

        if key not in analysis:

            raise RuntimeError(
                "Field AI tidak ditemukan: "
                + key
            )


    if not isinstance(
        analysis[
            "kemungkinan_penyebab"
        ],
        list
    ):

        raise RuntimeError(
            "kemungkinan_penyebab bukan list."
        )


    if not isinstance(
        analysis[
            "tindakan"
        ],
        list
    ):

        raise RuntimeError(
            "tindakan bukan list."
        )


    return analysis


# ============================================================
# PARSE RESPONSE
# ============================================================

def parse_gemini_response(
    response
):

    if response is None:

        raise RuntimeError(
            "Gemini memberikan response kosong."
        )


    parsed = getattr(
        response,
        "parsed",
        None
    )


    if isinstance(
        parsed,
        dict
    ):

        return validate_analysis(
            parsed
        )


    text = (
        response.text
        or ""
    ).strip()


    if not text:

        raise RuntimeError(
            "Gemini tidak menghasilkan text."
        )


    try:

        data = json.loads(
            text
        )

    except json.JSONDecodeError as error:

        raise RuntimeError(
            "Response Gemini bukan JSON valid: "
            + str(error)
        )


    return validate_analysis(
        data
    )


# ============================================================
# RETRY CHECK
# ============================================================

def is_retryable_api_error(error):

    if not isinstance(
        error,
        errors.APIError
    ):

        return True


    code = getattr(
        error,
        "code",
        None
    )


    return code in {
        429,
        500,
        502,
        503,
        504
    }


# ============================================================
# CALL GEMINI
# ============================================================

def call_gemini(
    client,
    alert
):

    prompt = (
        build_security_prompt(
            alert
        )
    )


    total_attempts = (
        GEMINI_RETRY_COUNT
        + 1
    )


    last_error = None


    for attempt in range(
        1,
        total_attempts + 1
    ):

        try:

            print(
                f"[GEMINI] Request "
                f"{attempt}/{total_attempts}"
            )


            response = (
                client.models.generate_content(

                    model=
                        GEMINI_MODEL,

                    contents=
                        prompt,

                    config=
                        types.GenerateContentConfig(

                            max_output_tokens=
                                GEMINI_MAX_OUTPUT_TOKENS,

                            thinking_config=
                                types.ThinkingConfig(

                                    thinking_level=
                                        GEMINI_THINKING_LEVEL
                                ),

                            # Kita tidak menggunakan tools.
                            automatic_function_calling=
                                types.AutomaticFunctionCallingConfig(
                                    disable=True
                                ),

                            response_mime_type=
                                "application/json",

                            response_json_schema=
                                AI_RESPONSE_SCHEMA
                        )
                )
            )


            analysis = (
                parse_gemini_response(
                    response
                )
            )


            return analysis


        except Exception as error:

            last_error = error


            print(
                "[GEMINI] Request gagal:",
                type(error).__name__,
                ":",
                error
            )


            retryable = (
                is_retryable_api_error(
                    error
                )
            )


            if (
                not retryable
                or
                attempt >= total_attempts
            ):

                break


            # =================================================
            # EXPONENTIAL BACKOFF + JITTER
            # =================================================

            base_wait = (
                2 ** (
                    attempt - 1
                )
            )


            wait_seconds = (
                base_wait
                + random.uniform(
                    0,
                    0.5
                )
            )


            print(
                "[GEMINI] Retry dalam "
                f"{wait_seconds:.1f} detik..."
            )


            time.sleep(
                wait_seconds
            )


    raise RuntimeError(
        "Gemini gagal setelah retry: "
        + str(
            last_error
        )
    )


# ============================================================
# ANALYZE + CACHE
# ============================================================

def analyze_wazuh_alert(
    client,
    alert
):

    cache = (
        cleanup_cache(
            load_cache()
        )
    )


    cache_key = (
        build_cache_key(
            alert
        )
    )


    cached_item = (
        cache.get(
            cache_key
        )
    )


    if cached_item:

        cached_analysis = (
            cached_item.get(
                "analysis"
            )
        )


        if isinstance(
            cached_analysis,
            dict
        ):

            print(
                "[AI CACHE] HIT"
            )


            return {

                "success":
                    True,

                "cached":
                    True,

                "analysis":
                    cached_analysis,

                "model":
                    cached_item.get(
                        "model",
                        GEMINI_MODEL
                    ),

                "cache_key":
                    cache_key
            }


    print(
        "[AI CACHE] MISS"
    )


    # ========================================================
    # LIVE GEMINI
    # ========================================================

    analysis = (
        call_gemini(
            client,
            alert
        )
    )


    # ========================================================
    # SAVE CACHE
    # ========================================================

    cache[
        cache_key
    ] = {

        "created_at":
            time.time(),

        "model":
            GEMINI_MODEL,

        "prompt_version":
            PROMPT_VERSION,

        "rule_id":
            alert.get(
                "rule_id"
            ),

        "level":
            alert.get(
                "level"
            ),

        "description":
            alert.get(
                "description"
            ),

        "target":
            extract_target(
                alert
            ),

        "analysis":
            analysis
    }


    cache = (
        cleanup_cache(
            cache
        )
    )


    save_cache(
        cache
    )


    return {

        "success":
            True,

        "cached":
            False,

        "analysis":
            analysis,

        "model":
            GEMINI_MODEL,

        "cache_key":
            cache_key
    }