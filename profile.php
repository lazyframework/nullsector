<?php
require __DIR__ . '/security.php';

if (empty($_SESSION['username'])) {
    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

$cfg = require __DIR__ . '/config.php';
$db  = $cfg['db'];

header('Content-Type: application/json; charset=utf-8');

$username = sec_sanitize($_GET['u'] ?? '', 32);
if ($username === '' || !sec_valid_username($username)) {
    echo json_encode(['error' => 'Username tidak valid']);
    exit;
}

try {
    $pdo = new PDO(
        "mysql:host={$db['host']};port={$db['port']};dbname={$db['name']};charset={$db['charset']}",
        $db['user'], $db['pass'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC, PDO::ATTR_EMULATE_PREPARES => false]
    );

    $stmt = $pdo->prepare(
        "SELECT id, username, color, bio, status, avatar, created_at, last_seen
         FROM users WHERE username = ? LIMIT 1"
    );
    $stmt->execute([$username]);
    $user = $stmt->fetch();

    if (!$user) {
        echo json_encode(['error' => 'User tidak ditemukan']);
        exit;
    }

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM messages WHERE username = ? AND type = 'msg'");
    $stmt->execute([$user['username']]);
    $totalMsg = (int)$stmt->fetchColumn();

    $stmt = $pdo->prepare("SELECT COUNT(*) FROM messages WHERE username = ? AND type = 'pm'");
    $stmt->execute([$user['username']]);
    $totalPm = (int)$stmt->fetchColumn();

    echo json_encode([
        'ok'        => true,
        'username'  => $user['username'],
        'color'     => $user['color'],
        'bio'       => $user['bio'] ?: 'Tidak ada bio.',
        'status'    => $user['status'] ?: '',
        'avatar'    => sec_avatar_url($user['avatar']),
        'joined'    => $user['created_at'],
        'last_seen' => $user['last_seen'],
        'total_msg' => $totalMsg,
        'total_pm'  => $totalPm,
    ]);

} catch (PDOException $e) {
    error_log('profile DB error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Terjadi kesalahan.']);
}
