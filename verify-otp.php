<?php
session_start();
require 'config.php';

$errors = [];
$success = "";

if (!isset($_SESSION['reset_email'])) {
    header('Location: forgot-password.php');
    exit;
}

$email = $_SESSION['reset_email'];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $input_otp = trim($_POST['otp'] ?? '');

    if (!$input_otp) {
        $errors[] = "Please enter the OTP.";
    } else {
        // Verify OTP and expiry from DB
        $stmt = mysqli_prepare($conn, "SELECT reset_token, reset_token_expiry FROM users WHERE email = ?");
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $db_otp, $expiry);
        mysqli_stmt_fetch($stmt);
        mysqli_stmt_close($stmt);

        if ($db_otp === null) {
            $errors[] = "No OTP requested. Please start again.";
        } elseif ($input_otp === $db_otp && strtotime($expiry) > time()) {
            // OTP valid: redirect to reset-password page
            header('Location: reset-password.php');
            exit;
        } else {
            $errors[] = "Invalid or expired OTP.";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Verify OTP</title>
</head>
<body>
<h2>Verify OTP</h2>

<?php if ($errors): ?>
    <div style="color:red;">
        <ul>
            <?php foreach ($errors as $e) echo "<li>" . htmlspecialchars($e) . "</li>"; ?>
        </ul>
    </div>
<?php endif; ?>

<form method="POST" action="verify-otp.php" novalidate>
    <label>Enter OTP: <input type="text" name="otp" required /></label><br/>
    <button type="submit">Verify OTP</button>
</form>

</body>
</html>
