<?php
/**
 * encrypt_helper.php
 * Enkripsi at-rest AES-256-GCM untuk body pesan di database.
 */

function enc_key(): string {
    $key = getenv('IRC_DB_KEY');
    if (!$key || strlen($key) !== 64) {
        $cfgFile = __DIR__ . '/config.php';
        if (is_file($cfgFile)) {
            $cfg = require $cfgFile;
            $key = $cfg['enc_key'] ?? '';
        }
    }
    if (!$key || strlen($key) !== 64 || !ctype_xdigit($key)) {
        throw new RuntimeException('IRC_DB_KEY tidak valid. Set 64 hex chars (32 byte) via env atau config.');
    }
    return hex2bin($key);
}

function enc_encrypt(string $plaintext): string {
    $key = enc_key();
    $iv  = random_bytes(12);
    $tag = '';
    $cipher = openssl_encrypt($plaintext, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
    if ($cipher === false) {
        throw new RuntimeException('Enkripsi gagal');
    }
    return 'enc1:' . base64_encode($iv . $tag . $cipher);
}

function enc_decrypt(string $encoded): string {
    if (strpos($encoded, 'enc1:') !== 0) {
        // Data lama belum terenkripsi — kembalikan apa adanya
        return $encoded;
    }
    try {
        $key  = enc_key();
        $data = base64_decode(substr($encoded, 5), true);
        if ($data === false || strlen($data) < 28) {
            return '[decrypt failed]';
        }
        $iv     = substr($data, 0, 12);
        $tag    = substr($data, 12, 16);
        $cipher = substr($data, 28);
        $plain  = openssl_decrypt($cipher, 'aes-256-gcm', $key, OPENSSL_RAW_DATA, $iv, $tag);
        return $plain === false ? '[decrypt failed]' : $plain;
    } catch (\Throwable $e) {
        return '[decrypt error]';
    }
}
