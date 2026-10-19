<?php
error_reporting(E_ALL);
ini_set('display_errors', 0);

require_once __DIR__ . '/security.php';
require_once __DIR__ . '/csrf.php';

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

header('Content-Type: application/json; charset=utf-8');

// Rate limit upload: 5x / 10 menit
if (!sec_rate_ok('upload_avatar', 5, 600)) {
    $wait = sec_rate_wait('upload_avatar', 600);
    echo json_encode(['error' => "Terlalu banyak upload. Tunggu {$wait} detik."]);
    exit;
}

// Cek ekstensi GD
if (!extension_loaded('gd') || !function_exists('imagecreatefromjpeg')) {
    echo json_encode(['error' => 'Server tidak mendukung GD (image processing). Hubungi admin.']);
    exit;
}

// Cek file
if (empty($_FILES['avatar']) || $_FILES['avatar']['error'] !== UPLOAD_ERR_OK) {
    $errMap = [
        UPLOAD_ERR_INI_SIZE   => 'File terlalu besar (batas server).',
        UPLOAD_ERR_FORM_SIZE  => 'File terlalu besar.',
        UPLOAD_ERR_PARTIAL    => 'Upload tidak lengkap.',
        UPLOAD_ERR_NO_FILE    => 'Tidak ada file yang di-upload.',
        UPLOAD_ERR_NO_TMP_DIR => 'Folder temporary server tidak ada.',
        UPLOAD_ERR_CANT_WRITE => 'Gagal menulis file ke disk.',
        UPLOAD_ERR_EXTENSION  => 'Upload dihentikan oleh ekstensi PHP.',
    ];
    $code = $_FILES['avatar']['error'] ?? UPLOAD_ERR_NO_FILE;
    echo json_encode(['error' => $errMap[$code] ?? 'Gagal upload file.']);
    exit;
}

$file = $_FILES['avatar'];

// Pastikan file benar-benar di-upload via HTTP POST
if (!is_uploaded_file($file['tmp_name'])) {
    echo json_encode(['error' => 'File upload tidak valid.']);
    exit;
}

if ($file['size'] > 2 * 1024 * 1024) {
    echo json_encode(['error' => 'Ukuran file maksimal 2 MB.']);
    exit;
}

// Cek MIME real
$finfo = finfo_open(FILEINFO_MIME_TYPE);
$mime  = finfo_file($finfo, $file['tmp_name']);
finfo_close($finfo);

$allowed = [
    'image/jpeg' => 'jpg',
    'image/png'  => 'png',
    'image/webp' => 'webp',
];

if (!isset($allowed[$mime])) {
    echo json_encode(['error' => 'Hanya JPG, PNG, atau WebP.']);
    exit;
}

// Cek gambar valid
$info = @getimagesize($file['tmp_name']);
if ($info === false) {
    echo json_encode(['error' => 'File bukan gambar yang valid.']);
    exit;
}

$ext = $allowed[$mime];
$uploadDir = __DIR__ . '/uploads/avatar/';

if (!is_dir($uploadDir)) {
    @mkdir($uploadDir, 0755, true);
}

if (!is_writable($uploadDir)) {
    echo json_encode(['error' => 'Folder uploads/avatar tidak writable.']);
    exit;
}

$username = $_SESSION['username'];
$filename = hash('sha256', $username . '_' . time() . '_' . bin2hex(random_bytes(8))) . '.' . $ext;
$targetPath = $uploadDir . $filename;

// Resize pakai GD
function resize_image($src, $dst, $mime, $maxSize = 256) {
    $img = null;
    switch ($mime) {
        case 'image/jpeg': $img = @imagecreatefromjpeg($src); break;
        case 'image/png':  $img = @imagecreatefrompng($src);  break;
        case 'image/webp': $img = @imagecreatefromwebp($src); break;
    }
    if (!$img) return false;

    $w = imagesx($img);
    $h = imagesy($img);

    if ($w > $maxSize || $h > $maxSize) {
        if ($w > $h) {
            $newW = $maxSize;
            $newH = (int)($h * ($maxSize / $w));
        } else {
            $newH = $maxSize;
            $newW = (int)($w * ($maxSize / $h));
        }
    } else {
        $newW = $w;
        $newH = $h;
    }

    $thumb = imagecreatetruecolor($newW, $newH);

    if ($mime === 'image/png' || $mime === 'image/webp') {
        imagealphablending($thumb, false);
        imagesavealpha($thumb, true);
        $transparent = imagecolorallocatealpha($thumb, 0, 0, 0, 127);
        imagefilledrectangle($thumb, 0, 0, $newW, $newH, $transparent);
    }

    imagecopyresampled($thumb, $img, 0, 0, 0, 0, $newW, $newH, $w, $h);

    $ok = false;
    switch ($mime) {
        case 'image/jpeg': $ok = imagejpeg($thumb, $dst, 88); break;
        case 'image/png':  $ok = imagepng($thumb, $dst, 8);   break;
        case 'image/webp': $ok = imagewebp($thumb, $dst, 88); break;
    }

    imagedestroy($img);
    imagedestroy($thumb);
    return $ok;
}

if (!resize_image($file['tmp_name'], $targetPath, $mime)) {
    echo json_encode(['error' => 'Gagal memproses gambar.']);
    exit;
}

// Update DB
$cfg = require __DIR__ . '/config.php';
$db  = $cfg['db'];

try {
    $pdo = new PDO(
        "mysql:host={$db['host']};port={$db['port']};dbname={$db['name']};charset={$db['charset']}",
        $db['user'], $db['pass'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]
    );

    $stmt = $pdo->prepare("SELECT avatar FROM users WHERE username = ? LIMIT 1");
    $stmt->execute([$username]);
    $oldAvatar = $stmt->fetchColumn();

    $stmt = $pdo->prepare("UPDATE users SET avatar = ? WHERE username = ?");
    $stmt->execute([$filename, $username]);

    if ($oldAvatar) {
        $oldPath = $uploadDir . $oldAvatar;
        // Pastikan path tetap di dalam folder avatar (cegah path traversal)
        $realOld = realpath($oldPath);
        $realDir = realpath($uploadDir);
        if ($realOld && $realDir && str_starts_with($realOld, $realDir) && is_file($realOld)) {
            @unlink($realOld);
        }
    }

    echo json_encode([
        'ok'     => true,
        'avatar' => $filename,
        'url'    => 'uploads/avatar/' . $filename,
    ]);

} catch (PDOException $e) {
    @unlink($targetPath);
    error_log('upload_avatar DB error: ' . $e->getMessage());
    http_response_code(500);
    echo json_encode(['error' => 'Terjadi kesalahan. Coba lagi nanti.']);
}
