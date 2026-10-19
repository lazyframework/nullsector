<?php
require __DIR__ . '/security.php';

// Generate 6 karakter (lebih kuat dari 5)
$chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
$code = '';
for ($i = 0; $i < 6; $i++) {
    $code .= $chars[random_int(0, strlen($chars) - 1)];
}

$_SESSION['captcha_code'] = $code;

// Ukuran gambar lebih besar
$width  = 180;
$height = 64;

$img = imagecreatetruecolor($width, $height);

// Background gelap merah
$bg = imagecolorallocate($img, 20, 0, 4);
imagefilledrectangle($img, 0, 0, $width, $height, $bg);

// Noise titik lebih banyak
for ($i = 0; $i < 350; $i++) {
    $c = imagecolorallocate($img, random_int(60, 160), 0, random_int(15, 50));
    imagesetpixel($img, random_int(0, $width), random_int(0, $height), $c);
}

// Noise garis lebih banyak + tebal
for ($i = 0; $i < 8; $i++) {
    $c = imagecolorallocate($img, random_int(80, 180), 0, random_int(15, 50));
    imagesetthickness($img, random_int(1, 2));
    imageline($img,
        random_int(0, $width), random_int(0, $height),
        random_int(0, $width), random_int(0, $height),
        $c);
}
imagesetthickness($img, 1);

// Arc noise
for ($i = 0; $i < 3; $i++) {
    $c = imagecolorallocate($img, random_int(70, 150), 0, random_int(10, 40));
    imagearc($img,
        random_int(0, $width), random_int(0, $height),
        random_int(20, 80), random_int(20, 60),
        random_int(0, 360), random_int(0, 360), $c);
}

// Tulis karakter
$fontFile = null;
$possibleFonts = [
    '/usr/share/fonts/truetype/dejavu/DejaVuSans-Bold.ttf',
    '/usr/share/fonts/truetype/liberation/LiberationSans-Bold.ttf',
];
foreach ($possibleFonts as $f) {
    if (is_file($f)) { $fontFile = $f; break; }
}

for ($i = 0; $i < 6; $i++) {
    $char = $code[$i];
    $x = 12 + ($i * 28);
    $y = random_int(40, 54);
    $color = imagecolorallocate($img,
        random_int(200, 255),
        random_int(15, 50),
        random_int(30, 70)
    );

    if ($fontFile) {
        $angle = random_int(-25, 25);
        $size  = random_int(18, 24);
        imagettftext($img, $size, $angle, $x, $y, $color, $fontFile, $char);
    } else {
        imagestring($img, 5, $x, $y - 15, $char, $color);
    }
}

// Border
$border = imagecolorallocate($img, 139, 0, 0);
imagerectangle($img, 0, 0, $width - 1, $height - 1, $border);

// Output PNG
header('Content-Type: image/png');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
header('Pragma: no-cache');
imagepng($img);
imagedestroy($img);
