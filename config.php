<?php
/**
 * config.php
 * Secrets diambil dari environment variable jika tersedia.
 * Jangan commit file yang berisi password/key asli.
 *
 * Generate key:  openssl rand -hex 32
 * Set env:       export IRC_DB_PASS='...' IRC_DB_KEY='...'
 */
$dbPass = getenv('IRC_DB_PASS');
$encKey = getenv('IRC_DB_KEY');

// Fallback HANYA untuk development lokal — hapus di production
if ($dbPass === false || $dbPass === '') {
    $dbPass = 'GantiPasswordKuat123!'; // TODO: ganti & pindah ke env
}
if ($encKey === false || $encKey === '' || strlen($encKey) !== 64) {
    $encKey = '0852cd02903ee6356ba1f5c206ab8bba6099890e65e1c0df5c5cbd2fac4b2c7a'; // TODO: ganti
}

return [
    'db' => [
        'host'    => getenv('IRC_DB_HOST') ?: '127.0.0.1',
        'port'    => (int)(getenv('IRC_DB_PORT') ?: 3306),
        'name'    => getenv('IRC_DB_NAME') ?: 'irc_chat',
        'user'    => getenv('IRC_DB_USER') ?: 'irc_app',
        'pass'    => $dbPass,
        'charset' => 'utf8mb4',
    ],
    'ws' => [
        'host' => getenv('IRC_WS_HOST') ?: '0.0.0.0',
        'port' => (int)(getenv('IRC_WS_PORT') ?: 8090),
    ],
    // 64 hex chars (32 byte)
    'enc_key' => $encKey,
];
