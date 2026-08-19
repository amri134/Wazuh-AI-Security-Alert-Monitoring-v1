import os
import sys

from dotenv import load_dotenv
from google import genai
from google.genai import types


# ============================================================
# LOAD ENV
# ============================================================

load_dotenv()


GEMINI_API_KEY = os.getenv(
    "GEMINI_API_KEY"
)

GEMINI_MODEL = os.getenv(
    "GEMINI_MODEL",
    "gemini-2.5-flash"
)


# ============================================================
# VALIDATION
# ============================================================

def validate_config():

    if not GEMINI_API_KEY:

        raise RuntimeError(
            "GEMINI_API_KEY belum tersedia di file .env"
        )

    if not GEMINI_MODEL:

        raise RuntimeError(
            "GEMINI_MODEL belum tersedia."
        )


# ============================================================
# MASK API KEY
# ============================================================

def mask_api_key(api_key):

    if not api_key:
        return "-"

    if len(api_key) <= 8:
        return "*" * len(api_key)

    return (
        api_key[:4]
        + ("*" * (len(api_key) - 8))
        + api_key[-4:]
    )


# ============================================================
# CREATE GEMINI CLIENT
# ============================================================

def create_client():

    return genai.Client(
        api_key=GEMINI_API_KEY
    )


# ============================================================
# TEST 1
# SIMPLE CONNECTION
# ============================================================

def test_basic_connection(client):

    print()
    print("=" * 70)
    print("[1] GEMINI BASIC CONNECTION TEST")
    print("=" * 70)

    print(
        "Model:",
        GEMINI_MODEL
    )

    print(
        "Mengirim request sederhana..."
    )


    response = client.models.generate_content(

        model=GEMINI_MODEL,

        contents=(
            "Balas hanya dengan teks berikut "
            "tanpa tambahan penjelasan: "
            "GEMINI CONNECTION SUCCESS"
        ),

        config=types.GenerateContentConfig(

            
            max_output_tokens=100
        )
    )


    if not response:

        raise RuntimeError(
            "Gemini tidak memberikan response."
        )


    text = response.text


    if not text:

        raise RuntimeError(
            "Response Gemini tidak memiliki text."
        )


    print()
    print(
        "Response:"
    )

    print(
        text.strip()
    )


    print()
    print(
        "[SUCCESS] Gemini API dapat diakses."
    )


    return True


# ============================================================
# SAMPLE WAZUH ALERT
# ============================================================

def get_sample_wazuh_alert():

    return {
        "timestamp":
            "2026-08-18T13:35:21.705Z",

        "agent_name":
            "resa",

        "agent_id":
            "001",

        "agent_ip":
            "10.130.81.214",

        "rule_id":
            "550",

        "level":
            7,

        "description":
            "Integrity checksum changed.",

        "groups": [
            "ossec",
            "syscheck",
            "syscheck_entry_modified",
            "syscheck_file"
        ],

        "location":
            "syscheck",

        "full_log":
            """
File 'c:\\wazuh-test\\telegram-test.txt' modified
Mode: realtime
Changed attributes: size,mtime,md5,sha1,sha256
Size changed from '21' to '46'
Old md5sum was: '317ed3cc229f12c59e369f7d96c5dfd9'
New md5sum is : 'f7f622582a60c73344b0cb2888845ff1'
Old sha1sum was: '3eb18ef44e5020ebfe37d607861335e39a13d754'
New sha1sum is : '2fa893338a622cc7d634af742f89f05af6e5e6f7'
Old sha256sum was: 'dc34f68bd62391cae9c2ee5a400ca236d4bb20eb2f9a1afcf14b9d2e2482c970'
New sha256sum is : '6270a0b45b7fde6a140b0c918938989ba969dc6eaf2b4734da37f92899a57bf3'
            """.strip()
    }


# ============================================================
# BUILD SECURITY ANALYSIS PROMPT
# ============================================================

def build_security_prompt(alert):

    groups = ", ".join(
        alert.get(
            "groups",
            []
        )
    )


    prompt = f"""
Anda adalah analis keamanan siber yang membantu menganalisis alert
dari Wazuh SIEM/XDR.

Analisis HANYA berdasarkan informasi yang tersedia pada alert.

ATURAN PENTING:

1. Jangan mengarang fakta yang tidak terdapat dalam alert.
2. Jangan mengatakan bahwa malware, attacker, ransomware,
   compromise, atau intrusi telah terjadi kecuali ada bukti
   yang mendukung hal tersebut.
3. Jika penyebab tidak dapat dipastikan, gunakan istilah:
   "kemungkinan", "dapat disebabkan oleh", atau
   "perlu verifikasi lebih lanjut".
4. Bedakan fakta yang diketahui dengan kemungkinan penyebab.
5. Jangan berikan penjelasan yang terlalu panjang.
6. Fokus pada tindakan praktis administrator/security analyst.
7. Gunakan Bahasa Indonesia.
8. Jangan menggunakan Markdown table.

DATA ALERT WAZUH:

Timestamp:
{alert.get("timestamp", "-")}

Agent:
{alert.get("agent_name", "-")}

Agent ID:
{alert.get("agent_id", "-")}

Agent IP:
{alert.get("agent_ip", "-")}

Rule ID:
{alert.get("rule_id", "-")}

Wazuh Level:
{alert.get("level", "-")}

Description:
{alert.get("description", "-")}

Groups:
{groups}

Location:
{alert.get("location", "-")}

Full Log:
{alert.get("full_log", "-")}


Berikan hasil dengan format PERSIS seperti ini:

RINGKASAN:
<Jelaskan secara singkat apa yang benar-benar terdeteksi.>

KEMUNGKINAN PENYEBAB:
<Jelaskan kemungkinan penyebab tanpa menganggap dugaan sebagai fakta.>

DAMPAK:
<Jelaskan dampak keamanan yang masuk akal berdasarkan alert.>

TINDAKAN YANG DISARANKAN:
1. <tindakan pertama>
2. <tindakan kedua>
3. <tindakan ketiga>

KESIMPULAN:
<Nyatakan apakah alert perlu diverifikasi, diperhatikan,
atau membutuhkan investigasi lebih lanjut.>
""".strip()


    return prompt


# ============================================================
# TEST 2
# WAZUH ALERT ANALYSIS
# ============================================================

def test_wazuh_analysis(client):

    print()
    print("=" * 70)
    print("[2] WAZUH LEVEL 7 AI ANALYSIS TEST")
    print("=" * 70)


    alert = get_sample_wazuh_alert()


    print(
        "Agent      :",
        alert["agent_name"]
    )

    print(
        "Rule ID    :",
        alert["rule_id"]
    )

    print(
        "Level      :",
        alert["level"]
    )

    print(
        "Description:",
        alert["description"]
    )


    prompt = build_security_prompt(
        alert
    )


    print()
    print(
        "[GEMINI] Menganalisis alert..."
    )


    response = client.models.generate_content(

        model=GEMINI_MODEL,

        contents=prompt,

        config=types.GenerateContentConfig(

            max_output_tokens=2500,
            thinking_config=types.ThinkingConfig(
                thinking_level="low"
            
        )
    )


    if not response:

        raise RuntimeError(
            "Gemini tidak memberikan response."
        )


    analysis = response.text


    if not analysis:

        raise RuntimeError(
            "Gemini tidak menghasilkan text analysis."
        )


    print()
    print("=" * 70)
    print("HASIL ANALISIS GEMINI")
    print("=" * 70)

    print()

    print(
        analysis.strip()
    )


    print()
    print("=" * 70)


    return analysis.strip()


# ============================================================
# MAIN
# ============================================================

def main():

    try:

        validate_config()


        print()
        print("=" * 70)
        print("GEMINI API TEST")
        print("=" * 70)


        print(
            "Model   :",
            GEMINI_MODEL
        )

        print(
            "API Key :",
            mask_api_key(
                GEMINI_API_KEY
            )
        )


        client = create_client()


        try:

            # =================================================
            # TEST 1
            # =================================================

            test_basic_connection(
                client
            )


            # =================================================
            # TEST 2
            # =================================================

            analysis = (
                test_wazuh_analysis(
                    client
                )
            )


            print()
            print("=" * 70)
            print("SEMUA TEST GEMINI BERHASIL")
            print("=" * 70)


            print(
                "✓ API key berhasil digunakan"
            )

            print(
                "✓ Model berhasil dipanggil"
            )

            print(
                "✓ Gemini dapat menganalisis alert Wazuh"
            )

            print(
                "✓ Level 7 sample berhasil dianalisis"
            )


        finally:

            # Tutup koneksi HTTP SDK.
            client.close()


    except KeyboardInterrupt:

        print()
        print(
            "[INFO] Program dihentikan."
        )


    except Exception as error:

        print()
        print("=" * 70)
        print("GEMINI TEST GAGAL")
        print("=" * 70)

        print(
            "Type :",
            type(error).__name__
        )

        print(
            "Error:",
            error
        )

        print()
        print(
            "Periksa GEMINI_API_KEY, GEMINI_MODEL, "
            "koneksi internet, dan kuota Gemini."
        )

        sys.exit(1)


if __name__ == "__main__":

    main()