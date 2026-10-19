<?php
/**
 * ws_refresh.php
 * Perpanjang / rotate WS token untuk user yang sedang login.
 * Dipanggil dari client sebelum token kadaluarsa.
 */
require __DIR__ . '/security.php';
require __DIR__ . '/csrf.php';

header('Content-Type: application/json; charset=utf-8');

if (empty($_SESSION['user_id']) || empty($_SESSION['username'])) {
    http_response_code(401);
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

csrf_check();

// Rate limit: max 10 refresh / 5 menit
if (!sec_rate_ok('ws_refresh', 10, 300)) {
    echo json_encode(['error' => 'Too many refresh attempts.']);
    exit;
}

$cfg = require __DIR__ . '/config.php';
$db  = $cfg['db'];

try {
    $pdo = new PDO(
        "mysql:host={$db['host']};port={$db['port']};dbname={$db['name']};charset={$db['charset']}",
        $db['user'], $db['pass'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]
    );

    // Rotate token setiap refresh (lebih aman)
    $wsToken = bin2hex(random_bytes(32));
    $ttl     = 1800; // 30 menit
    $expires = date('Y-m-d H:i:s', time() + $ttl);

    $stmt = $pdo->prepare(
        "UPDATE users SET ws_token = ?, ws_token_expires = ?, last_seen = NOW() WHERE id = ?"
    );
    $stmt->execute([$wsToken, $expires, (int)$_SESSION['user_id']]);

    $_SESSION['ws_token'] = $wsToken;
    $_SESSION['ws_token_expires_at'] = time() + $ttl;

    echo json_encode([
        'ok'         => true,
        'ws_token'   => $wsToken,
        'expires_in' => $ttl,
    ]);
} catch (PDOException $e) {
    error_log('ws_refresh DB error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Something went wrong.']);
}
