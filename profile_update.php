<?php
require __DIR__ . '/security.php';
require __DIR__ . '/csrf.php';

if (empty($_SESSION['username'])) {
    http_response_code(401);
    header('Content-Type: application/json');
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

csrf_check();

if (!sec_rate_ok('profile_update', 20, 600)) {
    echo json_encode(['error' => 'Terlalu banyak update. Coba lagi nanti.']);
    exit;
}

$cfg = require __DIR__ . '/config.php';
$db  = $cfg['db'];

header('Content-Type: application/json; charset=utf-8');

$bio    = sec_sanitize($_POST['bio'] ?? '', 200);
$status = sec_sanitize($_POST['status'] ?? '', 50);
$color  = (string)($_POST['color'] ?? '');

$allowedColors = ['u-green','u-cyan','u-yellow','u-red','u-purple','u-blue'];
if (!in_array($color, $allowedColors, true)) {
    $color = $_SESSION['color'] ?? 'u-green';
}

try {
    $pdo = new PDO(
        "mysql:host={$db['host']};port={$db['port']};dbname={$db['name']};charset={$db['charset']}",
        $db['user'], $db['pass'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]
    );

    $stmt = $pdo->prepare("UPDATE users SET bio = ?, status = ?, color = ? WHERE username = ?");
    $stmt->execute([$bio, $status, $color, $_SESSION['username']]);

    $_SESSION['color'] = $color;

    echo json_encode([
        'ok'     => true,
        'color'  => $color,
        'bio'    => $bio,
        'status' => $status,
    ]);

} catch (PDOException $e) {
    error_log('profile_update DB error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Terjadi kesalahan.']);
}
