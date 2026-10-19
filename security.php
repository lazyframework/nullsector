<?php
/**
 * security.php
 * Include di paling atas setiap file PHP yang butuh session / keamanan.
 */

if (session_status() === PHP_SESSION_NONE) {
    session_set_cookie_params([
        'lifetime' => 0,
        'path'     => '/',
        'domain'   => '',
        'secure'   => !empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off',
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

/* ============ HEADER KEAMANAN ============ */

if (!headers_sent()) {
    header('X-Content-Type-Options: nosniff');
    header('X-Frame-Options: DENY');
    header('X-XSS-Protection: 1; mode=block');
    header('Referrer-Policy: no-referrer');
    header('Permissions-Policy: geolocation=(), microphone=(), camera=()');
    // CSP: sesuaikan jika ada CDN/font lain
    header("Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self' ws: wss:; frame-ancestors 'none'; base-uri 'self'; form-action 'self'");
    // HSTS hanya jika HTTPS aktif
    $isHttps = (!empty($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off')
            || (isset($_SERVER['SERVER_PORT']) && (int)$_SERVER['SERVER_PORT'] === 443)
            || (!empty($_SERVER['HTTP_X_FORWARDED_PROTO']) && $_SERVER['HTTP_X_FORWARDED_PROTO'] === 'https');
    if ($isHttps) {
        header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
    }
    header_remove('X-Powered-By');
}

/* ============ CSRF ============ */

function csrf_token(): string {
    if (empty($_SESSION['csrf_token'])) {
        $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
    }
    return $_SESSION['csrf_token'];
}

function csrf_check(): void {
    $token = $_POST['csrf_token'] ?? '';
    $sess  = $_SESSION['csrf_token'] ?? '';

    if ($sess === '' || $token === '' || !hash_equals($sess, $token)) {
        http_response_code(403);
        header('Content-Type: text/plain; charset=utf-8');
        die('CSRF token tidak valid. Refresh halaman lalu coba lagi.');
    }
}

/* ============ SANITIZE ============ */

/**
 * Bersihkan string dari null byte, tag HTML, karakter kontrol, limit panjang.
 */
function sec_sanitize(string $str, int $maxLen = 500): string {
    $str = str_replace("\0", '', $str);
    $str = trim($str);
    $str = strip_tags($str);
    // hapus karakter kontrol kecuali \t (09) \n (0A) \r (0D)
    $str = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $str);
    if (mb_strlen($str, 'UTF-8') > $maxLen) {
        $str = mb_substr($str, 0, $maxLen, 'UTF-8');
    }
    return $str;
}

/**
 * Validasi username: 3-32 char, hanya a-zA-Z0-9_
 */
function sec_valid_username(string $u): bool {
    return (bool) preg_match('/^[a-zA-Z0-9_]{3,32}$/', $u);
}

/**
 * Escape untuk HTML output.
 */
function e(?string $s): string {
    return htmlspecialchars((string)$s, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
}

/* ============ RATE LIMIT (session-based) ============ */

/**
 * Cek apakah aksi diperbolehkan.
 * @param string $key     nama bucket (mis. 'login', 'register')
 * @param int    $limit   max percobaan
 * @param int    $window  window dalam detik
 * @return bool  true kalau masih boleh
 */
function sec_rate_ok(string $key, int $limit = 5, int $window = 60): bool {
    $now = time();
    $bucket = $_SESSION['_rl_' . $key] ?? [];
    $bucket = array_values(array_filter($bucket, fn($t) => ($now - $t) < $window));

    if (count($bucket) >= $limit) {
        $_SESSION['_rl_' . $key] = $bucket;
        return false;
    }
    $bucket[] = $now;
    $_SESSION['_rl_' . $key] = $bucket;
    return true;
}

/**
 * Berapa detik user harus tunggu.
 */
function sec_rate_wait(string $key, int $window = 60): int {
    $bucket = $_SESSION['_rl_' . $key] ?? [];
    if (empty($bucket)) return 0;
    $oldest = min($bucket);
    $wait = $window - (time() - $oldest);
    return max(0, $wait);
}

/**
 * Verifikasi captcha session (sekali pakai).
 * Mengembalikan true jika valid, false jika tidak.
 * Selalu menghapus captcha dari session setelah dicek.
 */
function sec_verify_captcha(string $input): bool {
    $input = strtoupper(trim($input));
    $sess  = $_SESSION['captcha_code'] ?? '';
    unset($_SESSION['captcha_code']);

    if ($sess === '' || $input === '') {
        return false;
    }
    return hash_equals($sess, $input);
}

/**
 * Bangun URL avatar aman dari filename di DB.
 * Hanya izinkan basename alfanumerik + titik/underscore/dash.
 * Mengembalikan path relatif atau null.
 */
function sec_avatar_url(?string $filename): ?string {
    if ($filename === null || $filename === '') {
        return null;
    }
    // Tolak path traversal / karakter aneh
    $base = basename($filename);
    if ($base !== $filename) {
        return null;
    }
    if (!preg_match('/^[a-zA-Z0-9._-]+\.(jpg|jpeg|png|webp)$/i', $base)) {
        return null;
    }
    return 'uploads/avatar/' . $base;
}
