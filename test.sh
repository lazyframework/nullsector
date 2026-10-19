#!/usr/bin/env bash
#
# test.sh — Security test suite untuk NullSector IRC
# Login otomatis: OCR captcha (channel R) + fallback cached session
#
# Usage:
#   ./test.sh <base_url> <username> <password>
# Contoh:
#   ./test.sh http://127.0.0.1:8080/nullsector LynxSaiko 1234567
#
# Requirement:
#   sudo apt install curl tesseract-ocr imagemagick
#
# PENTING: Jalankan hanya di dev/staging.

set -u
set -o pipefail

BASE_URL="${1:-}"
USERNAME="${2:-}"
PASSWORD="${3:-}"

if [[ -z "$BASE_URL" || -z "$USERNAME" || -z "$PASSWORD" ]]; then
    echo "Usage: $0 <base_url> <username> <password>"
    echo "Contoh: $0 http://127.0.0.1:8080/nullsector LynxSaiko 1234567"
    exit 1
fi

BASE_URL="${BASE_URL%/}"
# Untuk cookie jar netscape, host harus tanpa path
HOST=$(echo "$BASE_URL" | sed -E 's#^https?://([^/]+).*#\1#')
PATH_PREFIX=$(echo "$BASE_URL" | sed -E 's#^https?://[^/]+(/.*)?$#\1#')
[[ -z "$PATH_PREFIX" ]] && PATH_PREFIX="/"

CACHE_FILE="$HOME/.irc_sessid"

# ============================================================
# DEPENDENCY CHECK
# ============================================================
missing=()
for cmd in curl tesseract convert; do
    command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
done
if [[ ${#missing[@]} -gt 0 ]]; then
    echo "ERROR: dependency tidak ditemukan: ${missing[*]}"
    echo "Install: sudo apt install curl tesseract-ocr imagemagick"
    exit 1
fi

COOKIE_JAR="$(mktemp)"
TMP_DIR="$(mktemp -d)"
trap 'rm -f "$COOKIE_JAR"; rm -rf "$TMP_DIR"' EXIT

PASS=0; FAIL=0; SKIP=0; RESULTS=()

c_red()   { printf '\033[31m%s\033[0m\n' "$*"; }
c_green() { printf '\033[32m%s\033[0m\n' "$*"; }
c_yellow(){ printf '\033[33m%s\033[0m\n' "$*"; }
c_blue()  { printf '\033[34m%s\033[0m\n' "$*"; }
c_dim()   { printf '\033[2m%s\033[0m\n' "$*"; }

pass() { PASS=$((PASS+1)); RESULTS+=("PASS | $1"); printf '  %s %s\n' "$(c_green '✓ PASS')" "$1"; }
fail() { FAIL=$((FAIL+1)); RESULTS+=("FAIL | $1"); printf '  %s %s\n' "$(c_red '✗ FAIL')" "$1"; [[ -n "${2:-}" ]] && printf '         %s\n' "$(c_dim "$2")"; }
skip() { SKIP=$((SKIP+1)); RESULTS+=("SKIP | $1"); printf '  %s %s\n' "$(c_yellow '○ SKIP')" "$1"; }
section() { echo ""; c_blue "============================================================"; c_blue "  $1"; c_blue "============================================================"; }

# ============================================================
# CAPTCHA OCR — CHANNEL R + THRESHOLD TUNING
# ============================================================
ocr_with_threshold() {
    local img="$1"
    local th="$2"
    local work="$TMP_DIR/work_${th}.png"

    convert "$img" \
        -channel R -separate +channel \
        -threshold "${th}%" \
        -resize 400% \
        -negate \
        -bordercolor white -border 30 \
        -morphology Open Diamond:1 \
        "$work" 2>/dev/null || return 1

    local result
    result=$(tesseract "$work" stdout \
        --psm 7 \
        -c tessedit_char_whitelist=ABCDEFGHJKLMNPQRSTUVWXYZ23456789 \
        2>/dev/null | tr -d ' \n\r\t' | tr 'a-z' 'A-Z')
    echo "$result"
}

solve_captcha() {
    local img="$1"
    local best=""
    # Coba beberapa threshold; pilih hasil 6 char pertama
    for th in 50 45 55 40 60 35 65; do
        local result
        result=$(ocr_with_threshold "$img" "$th")
        if [[ ${#result} -eq 6 ]]; then
            echo "$result"
            return 0
        fi
        [[ -z "$best" && ${#result} -gt 0 ]] && best="$result"
    done
    # Kalau tidak ada yang pas 6 char, kembalikan yang terbaik (mungkin gagal nanti)
    echo "$best"
}

# ============================================================
# LOGIN via OCR
# ============================================================
login_with_ocr() {
    local max_attempts=10
    local attempt

    for attempt in $(seq 1 $max_attempts); do
        c_dim "  [login] attempt $attempt/$max_attempts"

        rm -f "$COOKIE_JAR"
        touch "$COOKIE_JAR"

        local login_html="$TMP_DIR/login_$attempt.html"
        local http_code
        http_code=$(curl -sS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
            -w "%{http_code}" -o "$login_html" \
            "$BASE_URL/login.php")

        if [[ "$http_code" != "200" ]]; then
            c_red "  [login] HTTP $http_code saat GET login.php"
            sleep 1
            continue
        fi

        # Cek rate limit di HTML
        if grep -q "Too many attempts" "$login_html"; then
            local wait
            wait=$(grep -oP 'wait \K[0-9]+' "$login_html" | head -n1)
            wait=${wait:-60}
            c_yellow "  [login] Rate limit — tunggu ${wait}s"
            sleep "$wait"
            continue
        fi

        local csrf
        csrf=$(grep -oP 'name="csrf_token"\s+value="\K[^"]+' "$login_html" | head -n1)
        if [[ -z "$csrf" ]]; then
            c_red "  [login] CSRF tidak ditemukan"
            sleep 1
            continue
        fi

        local cap_img="$TMP_DIR/captcha_$attempt.png"
        curl -sS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
            -o "$cap_img" \
            "$BASE_URL/captcha.php?t=$(date +%s%N)"

        if [[ ! -s "$cap_img" ]]; then
            c_red "  [login] Captcha image kosong"
            sleep 1
            continue
        fi

        local captcha
        captcha=$(solve_captcha "$cap_img")
        c_dim "  [login] OCR: '$captcha' (len=${#captcha})"

        if [[ ${#captcha} -ne 6 ]]; then
            continue
        fi

        curl -sS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
            -o /dev/null -w "" \
            -X POST "$BASE_URL/login_process.php" \
            --data-urlencode "username=$USERNAME" \
            --data-urlencode "password=$PASSWORD" \
            --data-urlencode "captcha=$captcha" \
            --data-urlencode "csrf_token=$csrf"

        local verify_code
        verify_code=$(curl -sS -c "$COOKIE_JAR" -b "$COOKIE_JAR" \
            -o "$TMP_DIR/index.html" -w "%{http_code}" \
            "$BASE_URL/index.php")

        if [[ "$verify_code" == "200" ]] && grep -q 'id="input"' "$TMP_DIR/index.html"; then
            return 0
        fi

        c_dim "  [login] login gagal (captcha salah?), retry"
    done

    return 1
}

# ============================================================
# MAIN LOGIN
# ============================================================
section "LOGIN (auto via OCR)"

LOGGED_IN=0

# 1. Coba cached session
if [[ -f "$CACHE_FILE" ]] && [[ -s "$CACHE_FILE" ]]; then
    MANUAL_SID=$(tr -d ' \n\r\t' < "$CACHE_FILE")
    if [[ -n "$MANUAL_SID" ]]; then
        c_dim "  [login] Coba cached session: ${MANUAL_SID:0:8}..."
        {
            echo "# Netscape HTTP Cookie File"
            printf '%s\t%s\t%s\t%s\t%d\t%s\t%s\n' \
                "$HOST" "FALSE" "$PATH_PREFIX" "FALSE" "0" "PHPSESSID" "$MANUAL_SID"
        } > "$COOKIE_JAR"

        VCODE=$(curl -sS -b "$COOKIE_JAR" -o "$TMP_DIR/index.html" -w "%{http_code}" "$BASE_URL/index.php")
        if [[ "$VCODE" == "200" ]] && grep -q 'id="input"' "$TMP_DIR/index.html"; then
            c_green "  ✓ Cached session valid"
            LOGGED_IN=1
            pass "Login via cached session (~/.irc_sessid)"
        else
            c_yellow "  ✗ Cached session expired, fallback ke OCR"
            rm -f "$CACHE_FILE"
        fi
    fi
fi

# 2. Kalau cached tidak valid, login via OCR
if [[ "$LOGGED_IN" == "0" ]]; then
    if login_with_ocr; then
        LOGGED_IN=1
        pass "Login berhasil (OCR captcha)"

        # Simpan PHPSESSID ke cache untuk run berikutnya
        SID=$(awk '/PHPSESSID/ {print $NF}' "$COOKIE_JAR" | tail -n1)
        if [[ -n "$SID" ]]; then
            echo "$SID" > "$CACHE_FILE"
            chmod 600 "$CACHE_FILE"
            c_dim "  Session disimpan di $CACHE_FILE"
        fi
    else
        fail "Login gagal setelah 10 percobaan"
        echo ""
        c_yellow "  Solusi cepat:"
        c_yellow "  1. Login manual di browser"
        c_yellow "  2. Copy PHPSESSID dari DevTools → Application → Cookies"
        c_yellow "  3. echo 'PASTE_SID' > ~/.irc_sessid"
        c_yellow "  4. Jalankan ulang script ini"
        exit 1
    fi
fi

CSRF_APP=$(grep -oP 'name="csrf-token" content="\K[^"]+' "$TMP_DIR/index.html" | head -n1)
if [[ -z "$CSRF_APP" ]]; then
    c_red "CSRF app token tidak ditemukan"
    exit 1
fi
c_dim "  CSRF app: ${CSRF_APP:0:16}..."

# ============================================================
# 1. SECURITY HEADERS
# ============================================================
section "1. SECURITY HEADERS"

HEADERS=$(curl -sS -I -b "$COOKIE_JAR" "$BASE_URL/index.php")

check_header() {
    local name="$1" pattern="$2" label="$3"
    if echo "$HEADERS" | grep -iq "$pattern"; then
        pass "$label"
    else
        fail "$label" "Header '$name' tidak ditemukan / tidak sesuai"
    fi
}

check_header "X-Content-Type-Options" "x-content-type-options: *nosniff" "X-Content-Type-Options: nosniff"
check_header "X-Frame-Options" "x-frame-options: *DENY" "X-Frame-Options: DENY"
check_header "Referrer-Policy" "referrer-policy: *no-referrer" "Referrer-Policy: no-referrer"
check_header "Content-Security-Policy" "content-security-policy:" "Content-Security-Policy ada"

CSP_LINE=$(echo "$HEADERS" | grep -i "content-security-policy:")
if echo "$CSP_LINE" | grep -qi "script-src[^;]*unsafe-inline"; then
    fail "CSP script-src tanpa 'unsafe-inline'" "Masih unsafe-inline — XSS inline masih mungkin"
else
    pass "CSP script-src tanpa 'unsafe-inline'"
fi

# ============================================================
# 2. SESSION & COOKIE
# ============================================================
section "2. SESSION & COOKIE"

if echo "$HEADERS" | grep -qi "set-cookie:.*HttpOnly"; then
    pass "Cookie HttpOnly"
else
    fail "Cookie HttpOnly"
fi

if echo "$HEADERS" | grep -qi "set-cookie:.*SameSite=Strict"; then
    pass "Cookie SameSite=Strict"
elif echo "$HEADERS" | grep -qi "set-cookie:.*SameSite=Lax"; then
    pass "Cookie SameSite=Lax"
else
    fail "Cookie SameSite" "Tidak ada SameSite"
fi

if [[ "$BASE_URL" == https://* ]]; then
    if echo "$HEADERS" | grep -qi "set-cookie:.*Secure"; then
        pass "Cookie Secure (HTTPS)"
    else
        fail "Cookie Secure" "HTTPS tapi Secure tidak ada"
    fi
else
    skip "Cookie Secure" "(HTTP — tidak bisa tes)"
fi

# ============================================================
# 3. CSRF
# ============================================================
section "3. CSRF"

test_csrf() {
    local endpoint="$1" data="$2" label="$3"
    local code
    code=$(curl -sS -o /dev/null -w "%{http_code}" \
        -b "$COOKIE_JAR" -X POST "$BASE_URL/$endpoint" $data)
    if [[ "$code" == "403" ]]; then
        pass "CSRF $label ditolak (403)"
    else
        fail "CSRF $label" "HTTP $code (harusnya 403)"
    fi
}

test_csrf "index.php?action=chat_send" "--data-urlencode text=CSRF_TEST --data-urlencode csrf_token=" "chat_send tanpa token"
test_csrf "index.php?action=chat_send" "--data-urlencode text=CSRF_TEST --data-urlencode csrf_token=deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef" "chat_send token salah"
test_csrf "profile_update.php" "--data-urlencode bio=csrf_test" "profile_update tanpa token"
test_csrf "index.php?action=typing" "--data-urlencode state=start" "typing tanpa token"
test_csrf "index.php?action=part" "--data-urlencode dummy=1" "part tanpa token"

# ============================================================
# 4. SQL INJECTION
# ============================================================
section "4. SQL INJECTION"

SQLI_RESP=$(curl -sS -b "$COOKIE_JAR" "$BASE_URL/profile.php?u=admin'--")
if echo "$SQLI_RESP" | grep -qi "SQL syntax\|mysql_\|PDOException"; then
    fail "SQLi profile.php?u=" "Response berisi SQL error"
elif echo "$SQLI_RESP" | grep -qi "tidak valid"; then
    pass "SQLi profile.php?u= ditolak (validasi username)"
else
    skip "SQLi profile.php?u=" "Response: ${SQLI_RESP:0:100}"
fi

SQLI_RESP=$(curl -sS -b "$COOKIE_JAR" "$BASE_URL/index.php?action=poll&last_msg=1'OR'1'='1&last_evt=0&last_pm=0")
if echo "$SQLI_RESP" | grep -q '"ok":true'; then
    pass "SQLi poll last_msg (integer cast)"
else
    fail "SQLi poll last_msg"
fi

SQLI_RESP=$(curl -sS -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/index.php?action=chat_send" \
    --data-urlencode "text=' OR 1=1 --" \
    --data-urlencode "csrf_token=$CSRF_APP")
if echo "$SQLI_RESP" | grep -q '"ok":true'; then
    pass "SQLi chat_send (prepared statement)"
elif echo "$SQLI_RESP" | grep -qi "SQL syntax\|PDOException"; then
    fail "SQLi chat_send" "SQL error muncul"
else
    skip "SQLi chat_send" "Response: ${SQLI_RESP:0:100}"
fi

# ============================================================
# 5. XSS (Stored)
# ============================================================
section "5. XSS (Stored)"

XSS_PAYLOADS=(
    "<script>alert('XSS1')</script>"
    "<img src=x onerror=alert('XSS2')>"
    "'\"><svg onload=alert('XSS3')>"
)

i=0
for payload in "${XSS_PAYLOADS[@]}"; do
    i=$((i+1))
    RESP=$(curl -sS -b "$COOKIE_JAR" \
        -X POST "$BASE_URL/index.php?action=chat_send" \
        --data-urlencode "text=$payload" \
        --data-urlencode "csrf_token=$CSRF_APP")
    if echo "$RESP" | grep -q '"ok":true'; then
        pass "XSS payload #$i terkirim (tersimpan sebagai text)"
    else
        skip "XSS payload #$i" "Response: ${RESP:0:100}"
    fi
    sleep 0.5   # hindari rate limit chat
done
c_yellow "  ! Verifikasi manual di browser — pastikan tidak ada alert()"

# ============================================================
# 6. UPLOAD AVATAR
# ============================================================
section "6. UPLOAD AVATAR"

SHELL_FILE="$TMP_DIR/shell.php"
echo '<?php system($_GET["cmd"] ?? "id"); ?>' > "$SHELL_FILE"

UPLOAD_RESP=$(curl -sS -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/upload_avatar.php" \
    -F "avatar=@$SHELL_FILE;type=image/jpeg;filename=shell.php" \
    -F "csrf_token=$CSRF_APP")

if echo "$UPLOAD_RESP" | grep -q '"error"'; then
    ERRMSG=$(echo "$UPLOAD_RESP" | grep -oP '"error":"\K[^"]+')
    pass "Upload PHP shell ditolak: $ERRMSG"
elif echo "$UPLOAD_RESP" | grep -q '"ok":true'; then
    FAIL_URL=$(echo "$UPLOAD_RESP" | grep -oP '"url":"\K[^"]+')
    fail "Upload PHP shell BERHASIL (RCE)" "File: $FAIL_URL"
else
    skip "Upload PHP shell" "Response: ${UPLOAD_RESP:0:200}"
fi

TXT_FILE="$TMP_DIR/test.txt"
echo "not an image" > "$TXT_FILE"

UPLOAD_RESP=$(curl -sS -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/upload_avatar.php" \
    -F "avatar=@$TXT_FILE;type=image/png" \
    -F "csrf_token=$CSRF_APP")

if echo "$UPLOAD_RESP" | grep -q '"error"'; then
    pass "Upload file non-image ditolak"
else
    fail "Upload file non-image" "Response: ${UPLOAD_RESP:0:200}"
fi

BIG_FILE="$TMP_DIR/big.jpg"
dd if=/dev/zero of="$BIG_FILE" bs=1024 count=3000 2>/dev/null

UPLOAD_RESP=$(curl -sS -b "$COOKIE_JAR" \
    -X POST "$BASE_URL/upload_avatar.php" \
    -F "avatar=@$BIG_FILE;type=image/jpeg" \
    -F "csrf_token=$CSRF_APP")

if echo "$UPLOAD_RESP" | grep -qi "maximal\|terlalu besar\|2 MB\|size"; then
    pass "Upload >2MB ditolak"
else
    fail "Upload >2MB" "Response: ${UPLOAD_RESP:0:200}"
fi

# ============================================================
# 7. RATE LIMIT
# ============================================================
section "7. RATE LIMIT"

RATE_CHAT_FAIL=0
for i in $(seq 1 7); do
    RESP=$(curl -sS -b "$COOKIE_JAR" \
        -X POST "$BASE_URL/index.php?action=chat_send" \
        --data-urlencode "text=RATE_TEST_$i" \
        --data-urlencode "csrf_token=$CSRF_APP")
    if echo "$RESP" | grep -qi "terlalu cepat\|too fast\|rate"; then
        RATE_CHAT_FAIL=$((RATE_CHAT_FAIL+1))
    fi
done

if [[ "$RATE_CHAT_FAIL" -gt 0 ]]; then
    pass "Rate limit chat aktif ($RATE_CHAT_FAIL/7 ditolak)"
else
    fail "Rate limit chat" "7 request semua lolos"
fi

# ============================================================
# 8. AUTHORIZATION / IDOR
# ============================================================
section "8. AUTHORIZATION / IDOR"

PROFILE_RESP=$(curl -sS -b "$COOKIE_JAR" "$BASE_URL/profile.php?u=$USERNAME")
if echo "$PROFILE_RESP" | grep -qi '"password"\|"ws_token"\|"hash"'; then
    fail "Profile.php bocorkan data sensitif"
else
    pass "Profile.php tidak bocorkan password/token"
fi

NOAUTH_JAR="$TMP_DIR/noauth.jar"
touch "$NOAUTH_JAR"

NOAUTH_RESP=$(curl -sS -o /dev/null -w "%{http_code}" -b "$NOAUTH_JAR" "$BASE_URL/index.php?action=poll&last_msg=0")
if [[ "$NOAUTH_RESP" == "401" || "$NOAUTH_RESP" == "302" ]]; then
    pass "Endpoint poll tanpa login ditolak (HTTP $NOAUTH_RESP)"
else
    fail "Endpoint poll tanpa login" "HTTP $NOAUTH_RESP"
fi

NOAUTH_RESP=$(curl -sS -o /dev/null -w "%{http_code}" -b "$NOAUTH_JAR" "$BASE_URL/index.php?action=pm_history&with=admin")
if [[ "$NOAUTH_RESP" == "401" || "$NOAUTH_RESP" == "302" ]]; then
    pass "PM history tanpa login ditolak (HTTP $NOAUTH_RESP)"
else
    fail "PM history tanpa login" "HTTP $NOAUTH_RESP"
fi

# ============================================================
# 9. PATH TRAVERSAL / FILE EXPOSURE
# ============================================================
section "9. PATH TRAVERSAL"

TRAV_RESP=$(curl -sS -b "$COOKIE_JAR" "$BASE_URL/profile.php?u=../../etc/passwd")
if echo "$TRAV_RESP" | grep -qi "root:.*:0:0:"; then
    fail "Path traversal profile.php" "Response berisi /etc/passwd"
elif echo "$TRAV_RESP" | grep -qi "tidak valid\|invalid"; then
    pass "Path traversal profile.php ditolak"
else
    skip "Path traversal profile.php" "Response tidak jelas"
fi

for f in "config.php" "security.php" "encrypt_helper.php" "data.sql" ".env" ".git/config"; do
    RESP_CODE=$(curl -sS -o /dev/null -w "%{http_code}" "$BASE_URL/$f")
    if [[ "$RESP_CODE" == "200" ]]; then
        BODY=$(curl -sS "$BASE_URL/$f")
        if echo "$BODY" | grep -q "<?php\|DB_PASS\|DB_KEY\|password"; then
            fail "File $f dapat diakses + bocorkan source" "HTTP 200"
        else
            pass "File $f 200 tapi kosong (tidak bocor)"
        fi
    elif [[ "$RESP_CODE" == "403" || "$RESP_CODE" == "404" ]]; then
        pass "File $f ditolak (HTTP $RESP_CODE)"
    else
        skip "File $f" "HTTP $RESP_CODE"
    fi
done

# ============================================================
# 10. HTTP METHOD ENFORCEMENT
# ============================================================
section "10. HTTP METHOD ENFORCEMENT"

METHOD_RESP=$(curl -sS -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" "$BASE_URL/index.php?action=chat_send&text=test")
[[ "$METHOD_RESP" == "405" ]] && pass "chat_send GET ditolak (405)" || fail "chat_send GET" "HTTP $METHOD_RESP"

METHOD_RESP=$(curl -sS -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" "$BASE_URL/profile_update.php")
[[ "$METHOD_RESP" == "405" ]] && pass "profile_update GET ditolak (405)" || fail "profile_update GET" "HTTP $METHOD_RESP"

METHOD_RESP=$(curl -sS -o /dev/null -w "%{http_code}" -b "$COOKIE_JAR" "$BASE_URL/upload_avatar.php")
[[ "$METHOD_RESP" == "405" ]] && pass "upload_avatar GET ditolak (405)" || fail "upload_avatar GET" "HTTP $METHOD_RESP"

# ============================================================
# RINGKASAN
# ============================================================
echo ""
c_blue "============================================================"
c_blue "  RINGKASAN"
c_blue "============================================================"
echo ""
printf '  %s: %d\n' "$(c_green 'PASS')" "$PASS"
printf '  %s: %d\n' "$(c_red   'FAIL')" "$FAIL"
printf '  %s: %d\n' "$(c_yellow 'SKIP')" "$SKIP"
echo ""

if [[ "$FAIL" -gt 0 ]]; then
    c_red "  ✗ ADA $FAIL KERENTANAN"
    echo ""
    for r in "${RESULTS[@]}"; do
        [[ "$r" == FAIL* ]] && printf '    %s\n' "$(c_red "$r")"
    done
    exit 1
else
    c_green "  ✓ Semua tes lulus."
    [[ "$SKIP" -gt 0 ]] && c_yellow "  ○ $SKIP tes di-skip — cek manual"
    exit 0
fi
