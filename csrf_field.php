<?php
/**
 * csrf_field.php
 * Helper untuk render input hidden CSRF.
 * Wajib include security.php dulu.
 */
if (!function_exists('csrf_token')) {
    require_once __DIR__ . '/security.php';
}
?>
<input type="hidden" name="csrf_token" value="<?= e(csrf_token()) ?>">
