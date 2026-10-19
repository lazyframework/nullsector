<?php
require __DIR__ . '/security.php';
require __DIR__ . '/csrf.php';

csrf_check();

$cfg = require __DIR__ . '/config.php';
$db  = $cfg['db'];

// Rate limit: 3 registrasi / 5 menit
if (!sec_rate_ok('register', 3, 300)) {
    $wait = sec_rate_wait('register', 300);
    $_SESSION['register_error'] = "Terlalu banyak pendaftaran. Tunggu {$wait} detik.";
    header('Location: register.php'); exit;
}

$username  = sec_sanitize($_POST['username'] ?? '', 32);
$password  = (string)($_POST['password'] ?? '');
$password2 = (string)($_POST['password2'] ?? '');

$_SESSION['old_register'] = ['username' => $username];

if ($username === '' || $password === '' || $password2 === '') {
    $_SESSION['register_error'] = 'Semua field wajib diisi.';
    header('Location: register.php'); exit;
}

if (!sec_valid_username($username)) {
    $_SESSION['register_error'] = 'Username harus 3-32 karakter, hanya huruf/angka/underscore.';
    header('Location: register.php'); exit;
}

if (strlen($password) < 8) {
    $_SESSION['register_error'] = 'Password minimal 8 karakter.';
    header('Location: register.php'); exit;
}

if (strlen($password) > 128) {
    $_SESSION['register_error'] = 'Password terlalu panjang.';
    header('Location: register.php'); exit;
}

if ($password !== $password2) {
    $_SESSION['register_error'] = 'Konfirmasi password tidak cocok.';
    header('Location: register.php'); exit;
}

// === Captcha (baru ditambahkan) ===
$captchaInput = (string)($_POST['captcha'] ?? '');
if (!sec_verify_captcha($captchaInput)) {
    $_SESSION['register_error'] = 'Captcha salah atau kosong. Coba lagi.';
    header('Location: register.php'); exit;
}
// === End Captcha ===

try {
    $pdo = new PDO(
        "mysql:host={$db['host']};port={$db['port']};dbname={$db['name']};charset={$db['charset']}",
        $db['user'], $db['pass'],
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );

    $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? LIMIT 1");
    $stmt->execute([$username]);
    if ($stmt->fetch()) {
        $_SESSION['register_error'] = 'Username sudah terpakai. Coba yang lain.';
        header('Location: register.php'); exit;
    }

    $palette = ['u-green','u-cyan','u-yellow','u-red','u-purple','u-blue'];
    $color = $palette[array_rand($palette)];

    $hash = password_hash($password, PASSWORD_DEFAULT);

    $stmt = $pdo->prepare(
        "INSERT INTO users (username, password, color, created_at)
         VALUES (?, ?, ?, NOW())"
    );
    $stmt->execute([$username, $hash, $color]);

    unset($_SESSION['old_register']);
    $_SESSION['register_success'] = 'Akun berhasil dibuat! Silakan login.';
    header('Location: login.php');
    exit;

} catch (PDOException $e) {
    error_log('register_process DB error: ' . $e->getMessage());
    $_SESSION['register_error'] = 'Terjadi kesalahan. Coba lagi nanti.';
    header('Location: register.php'); exit;
}
