<?php
session_start();
require 'config.php';

$errors = [];

if (!isset($_SESSION['pending_signup'])) {
    header('Location: sign-up.php');
    exit;
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $inputOtp = trim($_POST['email_otp_input'] ?? '');
    $sessionOtp = $_SESSION['email_otp'] ?? null;
    $otpExpiry = $_SESSION['otp_expiry'] ?? 0;

    if ($sessionOtp !== null && (string)$inputOtp === (string)$sessionOtp && time() < $otpExpiry) {
        $data = $_SESSION['pending_signup'];

        // Check duplicate again (to be safe)
        $stmt = mysqli_prepare($conn, "SELECT COUNT(*) FROM users WHERE email = ? OR username = ?");
        mysqli_stmt_bind_param($stmt, "ss", $data['email'], $data['username']);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $count);
        mysqli_stmt_fetch($stmt);
        mysqli_stmt_close($stmt);

        if ($count > 0) {
            $errors[] = "Username or email already taken.";
        } else {
            $stmt = mysqli_prepare($conn, "INSERT INTO users (first_name, last_name, dob, address, email, phone, username, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
            mysqli_stmt_bind_param($stmt, "ssssssss", $data['first_name'], $data['last_name'], $data['dob'], $data['address'], $data['email'], $data['phone'], $data['username'], $data['password_hash']);
            $exec = mysqli_stmt_execute($stmt);
            mysqli_stmt_close($stmt);

            if ($exec) {
                unset($_SESSION['pending_signup'], $_SESSION['email_otp'], $_SESSION['otp_expiry'], $_SESSION['email_to_verify']);
                $_SESSION['user'] = $data['username'];
                header('Location: index.php');
                exit;
            } else {
                $errors[] = "Database insert error: " . mysqli_error($conn);
            }
        }
    } else {
        $errors[] = "Invalid or expired verification code.";
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Email Verification - The Velvet Reel</title>
<style>
.error-messages { color: red; }
label { display: block; margin-top: 10px; }
</style>
</head>
<body>

<h2>Email Verification</h2>

<?php if ($errors): ?>
    <div class="error-messages">
        <ul>
            <?php foreach ($errors as $err): ?>
                <li><?= htmlspecialchars($err) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<form method="POST" action="verify-email.php" novalidate>
    <label>Enter Verification Code:
        <input type="text" name="email_otp_input" required />
    </label>
    <button type="submit">Verify</button>
</form>

</body>
</html>
