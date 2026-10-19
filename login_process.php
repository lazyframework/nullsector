<?php
require __DIR__ . '/security.php';
require __DIR__ . '/csrf.php';

csrf_check();

$cfg = require __DIR__ . '/config.php';
$db  = $cfg['db'];

// Rate limit: 5 attempts / 60 seconds
if (!sec_rate_ok('login', 5, 60)) {
    $wait = sec_rate_wait('login', 60);
    $_SESSION['login_error'] = "Too many attempts. Please wait {$wait} seconds.";
    header('Location: login.php'); exit;
}

$username = sec_sanitize($_POST['username'] ?? '', 32);
$password = (string)($_POST['password'] ?? '');

if ($username === '' || $password === '') {
    $_SESSION['login_error'] = 'Username and password are required.';
    header('Location: login.php'); exit;
}

if (!sec_valid_username($username)) {
    $_SESSION['login_error'] = 'Invalid username or password.';
    header('Location: login.php'); exit;
}

// === Verify Custom Captcha ===
$captchaInput = (string)($_POST['captcha'] ?? '');
if (!sec_verify_captcha($captchaInput)) {
    $_SESSION['login_error'] = 'Captcha is incorrect or missing. Try again.';
    header('Location: login.php'); exit;
}
// === End Custom Captcha ===

try {
    $pdo = new PDO(
        "mysql:host={$db['host']};port={$db['port']};dbname={$db['name']};charset={$db['charset']}",
        $db['user'], $db['pass'],
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );

    $stmt = $pdo->prepare("SELECT id, username, password, color FROM users WHERE username = ? LIMIT 1");
    $stmt->execute([$username]);
    $user = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$user || !password_verify($password, $user['password'])) {
        $_SESSION['login_error'] = 'Invalid username or password.';
        header('Location: login.php'); exit;
    }

    // Update last_seen saja (tanpa ws_token)
    $stmt = $pdo->prepare("UPDATE users SET last_seen = NOW() WHERE id = ?");
    $stmt->execute([$user['id']]);

    // === Session fixation prevention ===
    session_regenerate_id(true);

    $_SESSION['user_id']  = (int)$user['id'];
    $_SESSION['username'] = $user['username'];
    $_SESSION['color']    = $user['color'];

    // Reset rate limit
    unset($_SESSION['_rl_login']);

    header('Location: index.php');
    exit;

} catch (PDOException $e) {
    error_log('login_process DB error: ' . $e->getMessage());
    $_SESSION['login_error'] = 'Something went wrong. Please try again later.';
    header('Location: login.php'); exit;
}
