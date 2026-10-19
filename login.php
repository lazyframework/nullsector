<?php
require __DIR__ . '/security.php';

if (isset($_SESSION['username'])) { header('Location: index.php'); exit; }
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0, viewport-fit=cover">
<meta name="color-scheme" content="dark">
<title>Login — IRC</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;500;700&family=Creepster&family=Nosifer&family=Eater&display=swap" rel="stylesheet">
<style>
  * { margin: 0; padding: 0; box-sizing: border-box; }

  :root {
    --void:#000; --surface:#080202; --raised:#100404; --line:#1a0808;
    --line2:#2a0e0e; --text:#c9b8b8; --bright:#f5e6e6; --dim:#7a5555;
    --faint:#3a2020; --violet:#8b7bff; --ember:#ff2038; --blood:#8b0000;
    --blood-2:#ff0a3c; --ok:#3ddc97; --bad:#ff2038; --pm:#c678dd;
    --mono:'JetBrains Mono','SF Mono',Consolas,monospace;
    --horror:'Nosifer','Creepster',cursive;
  }

  html, body {
    min-height: 100vh;
    background: #000;
    color: var(--text);
    font-family: var(--mono);
    -webkit-font-smoothing: antialiased;
    display: flex;
    justify-content: center;
    align-items: center;
    padding: 20px;
    position: relative;
    overflow: hidden;
  }

  body::before {
    content: '';
    position: fixed; inset: 0; z-index: 0;
    background:
      radial-gradient(ellipse at 50% 40%, rgba(139,0,0,.35) 0%, rgba(60,0,0,.15) 30%, transparent 65%),
      radial-gradient(ellipse at 50% 100%, rgba(255,10,60,.12) 0%, transparent 50%);
    pointer-events: none;
    animation: pulseGlow 8s ease-in-out infinite;
  }
  @keyframes pulseGlow {
    0%, 100% { opacity: .8; }
    50%      { opacity: 1; }
  }

  body::after {
    content: '';
    position: fixed; inset: 0; z-index: 0;
    background-image:
      linear-gradient(rgba(139,0,0,.04) 1px, transparent 1px),
      linear-gradient(90deg, rgba(139,0,0,.04) 1px, transparent 1px),
      radial-gradient(ellipse at center, transparent 30%, rgba(0,0,0,.85) 100%);
    background-size: 40px 40px, 40px 40px, 100% 100%;
    pointer-events: none;
  }

  .box {
    position: relative;
    z-index: 1;
    width: 100%;
    max-width: 340px;
    background: rgba(8, 2, 2, 0.85);
    border: 1px solid var(--line2);
    border-radius: 6px;
    padding: 34px 24px 30px;
    box-shadow:
      0 0 0 1px rgba(255,10,60,.08),
      0 30px 80px rgba(0,0,0,.95),
      0 0 80px rgba(255,10,60,.12);
    backdrop-filter: blur(10px) saturate(0.85);
    -webkit-backdrop-filter: blur(10px) saturate(0.85);
    animation: boxIn .3s ease-out;
  }
  @keyframes boxIn {
    from { opacity: 0; transform: translateY(8px) scale(.98); }
    to   { opacity: 1; transform: translateY(0) scale(1); }
  }

  .box::before {
    content: '';
    position: absolute;
    top: -1px; left: 10%; right: 10%; height: 1px;
    background: linear-gradient(90deg, transparent, var(--blood-2), transparent);
    opacity: .8;
    animation: linePulse 3s ease-in-out infinite;
  }
  @keyframes linePulse {
    0%, 100% { opacity: .5; }
    50%      { opacity: 1; }
  }

  h1 {
    font-family: var(--horror);
    color: #cc0000;
    font-size: 40px;
    letter-spacing: 2px;
    line-height: 1.15;
    margin-bottom: 12px;
    text-align: center;
    text-shadow:
      0 0 5px rgba(255,0,0,.9),
      0 0 20px rgba(139,0,0,.95),
      0 0 40px rgba(80,0,0,.85),
      2px 2px 0 rgba(0,0,0,.9);
    animation: flicker 5s infinite, drip 4s ease-in-out infinite;
  }
  @keyframes flicker {
    0%,18%,22%,25%,53%,57%,100% { opacity: 1; }
    20%,24%,55% { opacity: .6; }
  }
  @keyframes drip {
    0%, 100% {
      text-shadow:
        0 0 5px rgba(255,0,0,.9),
        0 0 20px rgba(139,0,0,.95),
        0 0 40px rgba(80,0,0,.85),
        2px 2px 0 rgba(0,0,0,.9);
    }
    50% {
      text-shadow:
        0 0 8px rgba(255,0,0,1),
        0 0 30px rgba(139,0,0,1),
        0 0 60px rgba(80,0,0,.95),
        2px 4px 0 rgba(0,0,0,.9);
    }
  }

  .sub {
    color: var(--dim);
    font-size: 10.5px;
    font-style: italic;
    text-align: center;
    margin-bottom: 22px;
    letter-spacing: .5px;
  }
  .sub::before { content: '// '; color: var(--blood-2); opacity: .7; }

  label {
    display: block;
    color: var(--dim);
    font-size: 11.5px;
    margin-bottom: 5px;
    margin-top: 16px;
    letter-spacing: .3px;
  }
  label::before {
    content: '> ';
    color: var(--blood-2);
    opacity: .6;
  }

  input {
    width: 100%;
    background: rgba(0, 0, 0, 0.6);
    border: 1px solid var(--line2);
    color: var(--bright);
    padding: 10px 12px;
    border-radius: 4px;
    font-family: var(--mono);
    font-size: 12.5px;
    outline: none;
    transition: border-color .15s, box-shadow .15s, background .15s;
  }
  input::placeholder {
    color: var(--faint);
    font-style: italic;
  }
  input:focus {
    border-color: var(--blood-2);
    background: rgba(20, 0, 5, 0.7);
    box-shadow:
      0 0 0 2px rgba(255,10,60,.15),
      0 0 20px rgba(255,10,60,.25);
  }

  .captcha-wrap {
    display: flex;
    align-items: center;
    gap: 8px;
    margin-bottom: 8px;
  }
  .captcha-img {
    height: 64px;
    width: 180px;
    border: 1px solid var(--line2);
    border-radius: 4px;
    background: #000;
    display: block;
    user-select: none;
    -webkit-user-drag: none;
  }
  .btn-refresh {
    width: 38px !important;
    height: 64px;
    margin-top: 0 !important;
    padding: 0 !important;
    background: rgba(0,0,0,.6) !important;
    border: 1px solid var(--line2) !important;
    color: var(--blood-2) !important;
    font-size: 20px !important;
    text-transform: none !important;
    letter-spacing: 0 !important;
    display: flex;
    align-items: center;
    justify-content: center;
    transition: color .15s, border-color .15s, transform .3s !important;
    box-shadow: none !important;
    cursor: pointer;
  }
  .btn-refresh:hover {
    color: #fff !important;
    border-color: var(--blood-2) !important;
    transform: rotate(180deg);
    filter: none !important;
  }
  .captcha-input {
    text-transform: uppercase;
    letter-spacing: 3px;
    font-weight: 700;
    text-align: center;
  }

  button[type="submit"] {
    width: 100%;
    background: linear-gradient(180deg, #a00018 0%, #4a0008 100%);
    border: 1px solid #6b0012;
    color: #f5d5d5;
    font-weight: 700;
    padding: 12px;
    border-radius: 4px;
    cursor: pointer;
    font-family: var(--mono);
    font-size: 13px;
    letter-spacing: 1px;
    text-transform: uppercase;
    margin-top: 20px;
    box-shadow:
      0 0 12px rgba(139,0,0,.5),
      inset 0 0 15px rgba(0,0,0,.4);
    transition: filter .15s, transform .05s, box-shadow .15s, color .15s, background .15s;
  }
  button[type="submit"]:hover {
    background: linear-gradient(180deg, #c00020 0%, #5a000a 100%);
    color: #fff;
    box-shadow:
      0 0 20px rgba(255,10,60,.5),
      inset 0 0 15px rgba(0,0,0,.4);
  }
  button[type="submit"]:active { transform: scale(.99); }

  .err, .ok {
    padding: 9px 12px;
    border-radius: 4px;
    font-size: 11.5px;
    margin-bottom: 14px;
    border-left: 2px solid;
  }
  .err {
    background: rgba(255,10,60,.08);
    color: var(--bad);
    border-color: var(--blood-2);
  }
  .ok {
    background: rgba(61,220,151,.08);
    color: var(--ok);
    border-color: var(--ok);
  }

  .link {
    color: var(--dim);
    font-size: 11.5px;
    text-align: center;
    margin-top: 20px;
    padding-top: 14px;
    border-top: 1px solid var(--line);
  }
  .link a {
    color: var(--blood-2);
    text-decoration: none;
    transition: text-shadow .15s;
  }
  .link a:hover {
    text-shadow: 0 0 10px rgba(255,10,60,.7);
    text-decoration: underline;
  }

  @media (prefers-reduced-motion: reduce) {
    h1 { animation: none; }
    .box { animation: none; }
    body::before { animation: none; }
    .box::before { animation: none; }
    * { transition: none !important; }
  }
</style>
</head>
<body>

<div class="box">
  <h1>LOGIN</h1>
  <p class="sub">#null.sector — access restricted</p>

  <?php if (!empty($_SESSION['login_error'])): ?>
    <div class="err"><?= e($_SESSION['login_error']) ?></div>
    <?php unset($_SESSION['login_error']); ?>
  <?php endif; ?>

  <?php if (!empty($_SESSION['register_success'])): ?>
    <div class="ok"><?= e($_SESSION['register_success']) ?></div>
    <?php unset($_SESSION['register_success']); ?>
  <?php endif; ?>

  <form method="post" action="login_process.php" autocomplete="off">
    <?php require __DIR__ . '/csrf_field.php'; ?>
    
    <label>Username</label>
    <input type="text" name="username" required autofocus maxlength="32"
           pattern="[a-zA-Z0-9_]{3,32}" placeholder="enter username">

    <label>Password</label>
    <input type="password" name="password" required maxlength="128"
           placeholder="enter password">

    <label>Verification</label>
    <div class="captcha-wrap">
      <img src="captcha.php?t=<?= time() ?>" alt="captcha" id="captchaImg" class="captcha-img">
      <button type="button" class="btn-refresh" id="btnRefreshCaptcha" title="Refresh captcha">⟳</button>
    </div>
    <input type="text" name="captcha" required maxlength="6" autocomplete="off"
           placeholder="enter 6 characters" class="captcha-input">

    <button type="submit">Login</button>
  </form>

  <p class="link">No account? <a href="register.php">Register here</a></p>
</div>

<script>
(function () {
  const img = document.getElementById('captchaImg');
  const btn = document.getElementById('btnRefreshCaptcha');
  if (img && btn) {
    btn.addEventListener('click', () => {
      img.src = 'captcha.php?t=' + Date.now();
    });
  }
})();
</script>

</body>
</html>
