<?php
/**
 * csrf.php
 * Include di handler POST untuk cek CSRF.
 * Otomatis load security.php kalau belum, lalu jalankan csrf_check().
 */
if (!function_exists('csrf_check')) {
    require_once __DIR__ . '/security.php';
}
csrf_check();
