<?php
require __DIR__ . '/security.php';
require __DIR__ . '/csrf.php';

if (empty($_SESSION['username'])) {
    http_response_code(401);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => 'Unauthorized']);
    exit;
}

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Content-Type: application/json; charset=utf-8');
    echo json_encode(['error' => 'Method not allowed']);
    exit;
}

csrf_check();

$cfg = require __DIR__ . '/config.php';
$db  = $cfg['db'];

header('Content-Type: application/json; charset=utf-8');

// Rate limit: 1x ganti username per 24 jam
if (!sec_rate_ok('rename_username', 1, 86400)) {
    $wait = sec_rate_wait('rename_username', 86400);
    $hours = ceil($wait / 3600);
    echo json_encode(['error' => "Batas ganti username. Coba lagi dalam {$hours} jam."]);
    exit;
}

$newUsername  = sec_sanitize($_POST['new_username'] ?? '', 32);
$newUsername2 = sec_sanitize($_POST['new_username2'] ?? '', 32);
$password     = (string)($_POST['password'] ?? '');
$currentUser  = $_SESSION['username'];

// Validasi
if ($newUsername === '' || $password === '') {
    echo json_encode(['error' => 'Username baru dan password wajib diisi.']);
    exit;
}

if ($newUsername !== $newUsername2) {
    echo json_encode(['error' => 'Konfirmasi username tidak cocok.']);
    exit;
}

if (!sec_valid_username($newUsername)) {
    echo json_encode(['error' => 'Username harus 3-32 karakter, hanya huruf/angka/underscore.']);
    exit;
}

if (strcasecmp($newUsername, $currentUser) === 0) {
    echo json_encode(['error' => 'Username sama dengan sekarang.']);
    exit;
}

try {
    $pdo = new PDO(
        "mysql:host={$db['host']};port={$db['port']};dbname={$db['name']};charset={$db['charset']}",
        $db['user'], $db['pass'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]
    );

    // Verifikasi password
    $stmt = $pdo->prepare("SELECT id, password FROM users WHERE username = ? LIMIT 1");
    $stmt->execute([$currentUser]);
    $me = $stmt->fetch(PDO::FETCH_ASSOC);

    if (!$me || !password_verify($password, $me['password'])) {
        echo json_encode(['error' => 'Password salah.']);
        exit;
    }

    // Cek username baru sudah dipakai
    $stmt = $pdo->prepare("SELECT id FROM users WHERE username = ? LIMIT 1");
    $stmt->execute([$newUsername]);
    if ($stmt->fetch()) {
        echo json_encode(['error' => 'Username sudah dipakai. Coba yang lain.']);
        exit;
    }

    // Mulai transaksi supaya konsisten
    $pdo->beginTransaction();

    // 1. Update username di tabel users + reset token WS
    $stmt = $pdo->prepare(
        "UPDATE users
         SET username = ?, ws_token = NULL, ws_token_expires = NULL
         WHERE id = ?"
    );
    $stmt->execute([$newUsername, $me['id']]);

    // 2. Update semua pesan lama (username di messages)
    $stmt = $pdo->prepare("UPDATE messages SET username = ? WHERE user_id = ?");
    $stmt->execute([$newUsername, $me['id']]);

    // 3. Update target PM (username penerima di messages)
    $stmt = $pdo->prepare("UPDATE messages SET target = ? WHERE target = ?");
    $stmt->execute([$newUsername, $currentUser]);

    $pdo->commit();

    // 4. Update session
    $_SESSION['username'] = $newUsername;
    // Token WS di-reset → user harus login ulang untuk connect chat
    unset($_SESSION['ws_token']);

    echo json_encode([
        'ok'           => true,
        'new_username' => $newUsername,
        'message'      => 'Username berhasil diganti. Silakan login ulang.',
    ]);

} catch (PDOException $e) {
    if (isset($pdo) && $pdo->inTransaction()) {
        $pdo->rollBack();
    }
    error_log('rename_username DB error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Terjadi kesalahan. Coba lagi nanti.']);
}
