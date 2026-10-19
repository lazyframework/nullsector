<?php
date_default_timezone_set('UTC');

require __DIR__ . '/vendor/autoload.php';
require __DIR__ . '/encrypt_helper.php';

use Ratchet\MessageComponentInterface;
use Ratchet\ConnectionInterface;
use Ratchet\Server\IoServer;
use Ratchet\Http\HttpServer;
use Ratchet\WebSocket\WsServer;


function server_avatar_url(?string $filename): ?string {
    if ($filename === null || $filename === '') return null;
    $base = basename($filename);
    if ($base !== $filename) return null;
    if (!preg_match('/^[a-zA-Z0-9._-]+\.(jpg|jpeg|png|webp)$/i', $base)) return null;
    return 'uploads/avatar/' . $base;
}

class IRCChat implements MessageComponentInterface
{
    protected $clients;
    protected $users = [];
    protected $pdo;
    protected $historyLimit = 50;
    protected $channel = '#null.sector';
    protected $recentJoins = [];
    protected $msgCounts = [];
    protected $typingCounts = [];
    protected $authFailCounts = []; // IP => [timestamps]
    protected $ipConnections = [];  // IP => count of open connections

    public function __construct(PDO $pdo)
    {
        $this->clients = new \SplObjectStorage;
        $this->pdo = $pdo;
        echo "[BOOT] IRC Chat (MySQL) running on ws://0.0.0.0:8090\n";
        echo "[BOOT] Channel: {$this->channel}\n";
        echo "[BOOT] Timezone: UTC (client renders local time)\n";
    }

    public function onOpen(ConnectionInterface $conn)
    {
        $ip = $conn->remoteAddress ?? 'unknown';
        // Max 8 koneksi simultan per IP
        $count = $this->ipConnections[$ip] ?? 0;
        if ($count >= 8) {
            echo "[OPEN] rejected #{$conn->resourceId} dari {$ip} (too many connections)\n";
            $conn->close();
            return;
        }
        $this->ipConnections[$ip] = $count + 1;
        $conn->ircIp = $ip;

        $this->clients->attach($conn);
        echo "[OPEN] #{$conn->resourceId} dari {$ip}\n";

        foreach ($this->fetchHistory($this->historyLimit) as $r) {
            $conn->send(json_encode($r));
        }
    }

    public function onMessage(ConnectionInterface $from, $msg)
    {
        $data = json_decode($msg, true);
        if (!$data || !isset($data['type'])) return;

        switch ($data['type']) {
            case 'auth':          $this->handleAuth($from, $data);      break;
            case 'msg':           $this->handleMsg($from, $data);       break;
            case 'pm':            $this->handlePm($from, $data);        break;
            case 'pm_history':    $this->handlePmHistory($from, $data); break;
            case 'typing':        $this->handleTyping($from, $data);    break;
            case 'pubkey':        $this->handlePubkey($from, $data);    break;
            case 'get_pubkeys':   $this->handleGetPubkeys($from, $data);break;
        }
    }

    public function onClose(ConnectionInterface $conn)
    {
        unset($this->msgCounts[$conn->resourceId]);
        unset($this->typingCounts[$conn->resourceId]);
        $ip = $conn->ircIp ?? ($conn->remoteAddress ?? null);
        if ($ip && isset($this->ipConnections[$ip])) {
            $this->ipConnections[$ip] = max(0, $this->ipConnections[$ip] - 1);
            if ($this->ipConnections[$ip] === 0) unset($this->ipConnections[$ip]);
        }

        if (isset($this->users[$conn->resourceId])) {
            $u = $this->users[$conn->resourceId];
            unset($this->users[$conn->resourceId]);

            $text = 'has left ' . $this->channel;
            $payload = [
                'type' => 'sys', 'tag' => 'part',
                'time' => time(),
                'nick' => $u['username'],
                'text' => $text,
            ];
            $this->saveMessage($u['id'], $u['username'], $u['color'], 'part', $text, null);
            $this->broadcast($payload);
            $this->broadcastUserList();

            $this->broadcast([
                'type' => 'typing',
                'nick' => $u['username'],
                'state' => 'stop',
            ]);
        }
        $this->clients->detach($conn);
        echo "[CLOSE] #{$conn->resourceId}\n";
    }

    public function onError(ConnectionInterface $conn, \Exception $e)
    {
        echo "[ERROR] {$e->getMessage()}\n";
        $conn->close();
    }

    /* ============ AUTH ============ */

    private function handleAuth(ConnectionInterface $conn, array $data)
    {
        $username = trim($data['username'] ?? '');
        $token    = trim($data['password'] ?? '');
        $ip       = $conn->ircIp ?? ($conn->remoteAddress ?? 'unknown');

        // Rate limit auth gagal: max 10 / 5 menit per IP
        $now = time();
        $fails = $this->authFailCounts[$ip] ?? [];
        $fails = array_values(array_filter($fails, fn($t) => ($now - $t) < 300));
        $this->authFailCounts[$ip] = $fails;
        if (count($fails) >= 10) {
            $conn->send(json_encode(['type' => 'auth_fail', 'reason' => 'Terlalu banyak percobaan auth']));
            return;
        }

        if ($username === '' || $token === '') {
            $this->authFailCounts[$ip][] = $now;
            $conn->send(json_encode(['type' => 'auth_fail', 'reason' => 'Data tidak lengkap']));
            return;
        }
        if (!preg_match('/^[a-zA-Z0-9_]{3,32}$/', $username)) {
            $this->authFailCounts[$ip][] = $now;
            $conn->send(json_encode(['type' => 'auth_fail', 'reason' => 'Username tidak valid']));
            return;
        }
        // Token harus 64 hex chars
        if (!preg_match('/^[a-f0-9]{64}$/', $token)) {
            $this->authFailCounts[$ip][] = $now;
            $conn->send(json_encode(['type' => 'auth_fail', 'reason' => 'Token invalid/expired']));
            return;
        }

        // Tutup koneksi lama dengan username sama
        $toClose = [];
        foreach ($this->users as $connId => $u) {
            if (strcasecmp($u['username'], $username) === 0) {
                foreach ($this->clients as $client) {
                    if ($client->resourceId == $connId) {
                        $toClose[] = $client;
                        break;
                    }
                }
            }
        }
        foreach ($toClose as $oldConn) {
            $oldId = $oldConn->resourceId;
            echo "[AUTH] {$username} re-login, tutup koneksi lama #{$oldId}\n";
            unset($this->users[$oldId]);
            try { $oldConn->close(); } catch (\Exception $e) {}
        }

        $stmt = $this->pdo->prepare(
            "SELECT id, username, color, avatar FROM users
             WHERE username = ? AND ws_token = ? AND ws_token_expires > NOW() LIMIT 1"
        );
        $stmt->execute([$username, $token]);
        $user = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$user) {
            $this->authFailCounts[$ip][] = $now;
            $conn->send(json_encode(['type' => 'auth_fail', 'reason' => 'Token invalid/expired']));
            return;
        }
        // Reset fail counter on success
        unset($this->authFailCounts[$ip]);

        // Update last_seen, TIDAK NULL-kan token (biar bisa reconnect)
        $this->pdo->prepare("UPDATE users SET last_seen = NOW() WHERE id = ?")
                  ->execute([$user['id']]);

        $this->users[$conn->resourceId] = [
            'id'       => (int)$user['id'],
            'username' => $user['username'],
            'color'    => $user['color'],
            'avatar'   => server_avatar_url($user['avatar']),
        ];

        $conn->send(json_encode([
            'type'   => 'welcome',
            'nick'   => $user['username'],
            'color'  => $user['color'],
            'avatar' => $this->users[$conn->resourceId]['avatar'],
        ]));

        // Cek rejoin: kalau join dalam 5 menit terakhir, skip broadcast
        $isRejoin = isset($this->recentJoins[$user['username']])
                 && (time() - $this->recentJoins[$user['username']]) < 300;

        if (!$isRejoin) {
            $text = 'has joined ' . $this->channel;
            $payload = [
                'type' => 'sys', 'tag' => 'join',
                'time' => time(),
                'nick' => $user['username'],
                'text' => $text,
            ];
            $this->saveMessage($user['id'], $user['username'], $user['color'], 'join', $text, null);
            $this->broadcast($payload);
        } else {
            echo "[AUTH] {$user['username']} reconnect (skip join)\n";
        }
        $this->recentJoins[$user['username']] = time();
        $this->broadcastUserList();
    }

    /* ============ MESSAGE ============ */

    private function handleMsg(ConnectionInterface $from, array $data)
    {
        if (!isset($this->users[$from->resourceId])) return;

        $u = $this->users[$from->resourceId];
        $text = $this->sanitize($data['text'] ?? '');
        if ($text === '') return;
        if (substr($text, 0, 1) === '/') return;

        $now = microtime(true);
        $rid = $from->resourceId;
        if (!isset($this->msgCounts[$rid])) $this->msgCounts[$rid] = [];
        $this->msgCounts[$rid] = array_values(array_filter(
            $this->msgCounts[$rid], fn($t) => ($now - $t) < 3
        ));
        if (count($this->msgCounts[$rid]) >= 5) {
            $from->send(json_encode(['type' => 'error', 'reason' => 'Terlalu cepat. Tunggu sebentar.']));
            return;
        }
        $this->msgCounts[$rid][] = $now;

        $stmt = $this->pdo->prepare("SELECT color, avatar FROM users WHERE id = ? LIMIT 1");
        $stmt->execute([$u['id']]);
        $fresh = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($fresh) {
            $u['color'] = $fresh['color'];
            $u['avatar'] = server_avatar_url($fresh['avatar']);
            $this->users[$from->resourceId]['color'] = $u['color'];
            $this->users[$from->resourceId]['avatar'] = $u['avatar'];
        }

        echo "[MSG] {$u['username']}: " . mb_substr($text, 0, 60) . "\n";

        $payload = [
            'type'   => 'msg',
            'time'   => time(),
            'nick'   => $u['username'],
            'color'  => $u['color'],
            'avatar' => $u['avatar'],
            'text'   => $text,
        ];
        $this->saveMessage($u['id'], $u['username'], $u['color'], 'msg', $text, null);
        $this->broadcast($payload);
    }

    /* ============ PM (E2E) ============ */

    private function handlePm(ConnectionInterface $from, array $data)
    {
        if (!isset($this->users[$from->resourceId])) return;
        $u = $this->users[$from->resourceId];

        $target = trim($data['target'] ?? '');
        $text   = $this->sanitize($data['text'] ?? '');
        $enc    = $data['enc'] ?? null;

        if ($target === '') return;
        if (!preg_match('/^[a-zA-Z0-9_]{3,32}$/', $target)) return;
        if ($text === '' && !$enc) return;

        $now = microtime(true);
        $rid = $from->resourceId;
        $key = 'pm_' . $rid;
        if (!isset($this->msgCounts[$key])) $this->msgCounts[$key] = [];
        $this->msgCounts[$key] = array_values(array_filter(
            $this->msgCounts[$key], fn($t) => ($now - $t) < 5
        ));
        if (count($this->msgCounts[$key]) >= 10) {
            $from->send(json_encode(['type' => 'error', 'reason' => 'Terlalu banyak PM.']));
            return;
        }
        $this->msgCounts[$key][] = $now;

        $stmt = $this->pdo->prepare("SELECT color, avatar FROM users WHERE id = ? LIMIT 1");
        $stmt->execute([$u['id']]);
        $fresh = $stmt->fetch(PDO::FETCH_ASSOC);
        if ($fresh) {
            $u['color'] = $fresh['color'];
            $u['avatar'] = server_avatar_url($fresh['avatar']);
            $this->users[$from->resourceId]['color'] = $u['color'];
            $this->users[$from->resourceId]['avatar'] = $u['avatar'];
        }

        $targetConn = null;
        $targetName = null;
        foreach ($this->users as $connId => $usr) {
            if (strcasecmp($usr['username'], $target) === 0) {
                $targetName = $usr['username'];
                foreach ($this->clients as $client) {
                    if ($client->resourceId == $connId) { $targetConn = $client; break; }
                }
                break;
            }
        }

        if (!$targetConn) {
            $from->send(json_encode(['type' => 'pm_fail', 'reason' => "User '$target' tidak online"]));
            return;
        }

        $payload = [
            'type'   => 'pm',
            'time'   => time(),
            'nick'   => $u['username'],
            'color'  => $u['color'],
            'avatar' => $u['avatar'],
            'target' => $targetName,
            'text'   => $text,
            'enc'    => $enc,
        ];

        $bodyToSave = $enc ? json_encode($enc) : $text;
        $this->saveMessage($u['id'], $u['username'], $u['color'], 'pm', $bodyToSave, $targetName);

        $targetConn->send(json_encode($payload));
        $from->send(json_encode($payload));
    }

    private function handlePmHistory(ConnectionInterface $conn, array $data)
    {
        if (!isset($this->users[$conn->resourceId])) return;
        $me = $this->users[$conn->resourceId]['username'];
        $other = trim($data['with'] ?? '');
        if ($other === '' || !preg_match('/^[a-zA-Z0-9_]{3,32}$/', $other)) return;

        $stmt = $this->pdo->prepare(
            "SELECT m.username, m.color, m.body, m.created_at, u.avatar
             FROM messages m
             LEFT JOIN users u ON u.username = m.username
             WHERE m.type = 'pm'
               AND ((m.username = ? AND m.target = ?) OR (m.username = ? AND m.target = ?))
             ORDER BY m.id DESC LIMIT 50"
        );
        $stmt->execute([$me, $other, $other, $me]);
        $rows = array_reverse($stmt->fetchAll(PDO::FETCH_ASSOC));

        $msgs = [];
        foreach ($rows as $r) {
            $body = enc_decrypt($r['body']);
            $enc = null;
            $maybe = json_decode($body, true);
            if (is_array($maybe) && isset($maybe['c']) && isset($maybe['k'])) {
                $enc = $maybe;
                $body = '';
            }
            $msgs[] = [
                'time'   => strtotime($r['created_at'] . ' UTC'),
                'nick'   => $r['username'],
                'color'  => $r['color'],
                'avatar' => server_avatar_url($r['avatar']),
                'text'   => $body,
                'enc'    => $enc,
            ];
        }

        $conn->send(json_encode([
            'type' => 'pm_history',
            'with' => $other,
            'msgs' => $msgs,
        ]));
    }

    /* ============ TYPING ============ */

    private function handleTyping(ConnectionInterface $from, array $data)
    {
        if (!isset($this->users[$from->resourceId])) return;
        $u = $this->users[$from->resourceId];
        $state = ($data['state'] ?? 'start') === 'start' ? 'start' : 'stop';

        $now = microtime(true);
        $rid = $from->resourceId;
        $key = 'typing_' . $rid;
        if (!isset($this->typingCounts[$key])) $this->typingCounts[$key] = 0;
        if ($state === 'start' && ($now - $this->typingCounts[$key]) < 1.5) return;
        $this->typingCounts[$key] = $now;

        $payload = json_encode([
            'type'  => 'typing',
            'nick'  => $u['username'],
            'state' => $state,
        ]);
        foreach ($this->clients as $client) {
            if ($client !== $from) $client->send($payload);
        }
    }

    /* ============ PUBKEY (E2E) ============ */

    private function handlePubkey(ConnectionInterface $conn, array $data)
    {
        if (!isset($this->users[$conn->resourceId])) return;
        $u = $this->users[$conn->resourceId];
        $pubkey = trim($data['pubkey'] ?? '');
        if ($pubkey === '') return;

        $jwk = json_decode($pubkey, true);
        if (!is_array($jwk) || ($jwk['kty'] ?? '') !== 'RSA') {
            $conn->send(json_encode(['type' => 'error', 'reason' => 'Public key tidak valid']));
            return;
        }

        $stmt = $this->pdo->prepare("UPDATE users SET pubkey = ? WHERE id = ?");
        $stmt->execute([$pubkey, $u['id']]);
        $this->users[$conn->resourceId]['pubkey'] = $pubkey;

        $conn->send(json_encode(['type' => 'pubkey_saved', 'ok' => true]));
    }

    private function handleGetPubkeys(ConnectionInterface $conn, array $data)
    {
        $usernames = $data['usernames'] ?? [];
        if (!is_array($usernames) || empty($usernames)) {
            $conn->send(json_encode(['type' => 'pubkeys', 'keys' => []]));
            return;
        }

        $placeholders = implode(',', array_fill(0, count($usernames), '?'));
        $stmt = $this->pdo->prepare("SELECT username, pubkey FROM users WHERE username IN ($placeholders)");
        $stmt->execute($usernames);
        $rows = $stmt->fetchAll(PDO::FETCH_ASSOC);

        $keys = [];
        foreach ($rows as $r) {
            $keys[$r['username']] = $r['pubkey'];
        }
        $conn->send(json_encode(['type' => 'pubkeys', 'keys' => $keys]));
    }

    /* ============ UTILS ============ */

    private function broadcastUserList()
    {
        $list = [];
        foreach ($this->users as $u) $list[] = $u['username'];
        $payload = json_encode(['type' => 'users', 'users' => $list]);
        foreach ($this->clients as $client) $client->send($payload);
    }

    private function saveMessage($userId, $username, $color, $type, $body, $target = null)
    {
        $encrypted = enc_encrypt($body);
        $stmt = $this->pdo->prepare(
            "INSERT INTO messages (user_id, username, target, color, type, body, created_at)
             VALUES (?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())"
        );
        $stmt->execute([$userId, $username, $target, $color, $type, $encrypted]);
    }

    private function fetchHistory($limit)
    {
        $limit = (int)$limit;
        $stmt = $this->pdo->query(
            "SELECT m.username, m.color, m.type, m.body, m.created_at, u.avatar
             FROM messages m
             LEFT JOIN users u ON u.username = m.username
             WHERE m.type IN ('msg','join','part')
             ORDER BY m.id DESC LIMIT $limit"
        );
        $rows = array_reverse($stmt->fetchAll(PDO::FETCH_ASSOC));

        $out = [];
        foreach ($rows as $r) {
            $time = strtotime($r['created_at'] . ' UTC');
            if ($r['type'] === 'msg') {
                $out[] = [
                    'type'   => 'msg',
                    'time'   => $time,
                    'nick'   => $r['username'],
                    'color'  => $r['color'],
                    'avatar' => server_avatar_url($r['avatar']),
                    'text'   => enc_decrypt($r['body']),
                ];
            } else {
                $out[] = [
                    'type' => 'sys',
                    'tag'  => $r['type'] === 'join' ? 'join' : 'part',
                    'time' => $time,
                    'nick' => $r['username'],
                    'text' => enc_decrypt($r['body']),
                ];
            }
        }
        return $out;
    }

    private function broadcast(array $payload)
    {
        $json = json_encode($payload);
        foreach ($this->clients as $client) $client->send($json);
    }

    private function sanitize($str)
    {
        $str = str_replace("\0", '', (string)$str);
        $str = trim($str);
        $str = strip_tags($str);
        $str = preg_replace('/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/u', '', $str);
        return mb_substr($str, 0, 500, 'UTF-8');
    }
}

/* ============ BOOT ============ */
$cfg = require __DIR__ . '/config.php';
$db  = $cfg['db'];

try {
    $pdo = new PDO(
        "mysql:host={$db['host']};port={$db['port']};dbname={$db['name']};charset={$db['charset']}",
        $db['user'], $db['pass'],
        [
            PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES   => false,
        ]
    );
    $pdo->exec("SET time_zone = '+00:00'");
} catch (PDOException $e) {
    error_log('server DB error: ' . $e->getMessage());
    die("[FATAL] Koneksi database gagal. Cek config.php.\n");
}

$server = IoServer::factory(
    new HttpServer(new WsServer(new IRCChat($pdo))),
    $cfg['ws']['port'],
    $cfg['ws']['host']
);
$server->run();
