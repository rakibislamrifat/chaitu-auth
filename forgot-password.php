<?php
session_start();
require 'config.php';

$errors = [];
$success = "";

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    
    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Please enter a valid email address.";
    } else {
        // Check if email exists
        $stmt = mysqli_prepare($conn, "SELECT id FROM users WHERE email = ?");
        mysqli_stmt_bind_param($stmt, "s", $email);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $user_id);
        mysqli_stmt_fetch($stmt);
        mysqli_stmt_close($stmt);

        if ($user_id) {
            // Generate token and expiry (e.g., 1 hour)
            $token = bin2hex(random_bytes(32)); // 64 chars
            $expiry = date("Y-m-d H:i:s", strtotime("+1 hour"));

            // Save token and expiry in DB
            $stmt = mysqli_prepare($conn, "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?");
            mysqli_stmt_bind_param($stmt, "ssi", $token, $expiry, $user_id);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_close($stmt);

            // Send reset email (use PHPMailer or mail())
            $resetLink = "https://yourdomain.com/reset-password.php?token=$token";

            $subject = "Password Reset Request";
            $message = "Hello,\n\nWe received a request to reset your password. "
                     . "Please click the link below to reset your password:\n\n"
                     . "$resetLink\n\n"
                     . "This link will expire in 1 hour.\n\n"
                     . "If you didn't request this, please ignore this email.";

            // Use mail() or PHPMailer here
            mail($email, $subject, $message, "From: no-reply@yourdomain.com");

            $success = "Password reset instructions have been sent to your email.";
        } else {
            $errors[] = "No account found with that email address.";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head><title>Forgot Password</title></head>
<body>
<h2>Forgot Password</h2>

<?php if ($errors): ?>
<div style="color:red;">
    <ul>
        <?php foreach ($errors as $e) echo "<li>" . htmlspecialchars($e) . "</li>"; ?>
    </ul>
</div>
<?php endif; ?>

<?php if ($success): ?>
<div style="color:green;">
    <?= htmlspecialchars($success) ?>
</div>
<?php endif; ?>

<form method="POST" action="forgot-password.php" novalidate>
    <label>Email: <input type="email" name="email" required /></label><br/>
    <button type="submit">Send Reset Link</button>
</form>

</body>
</html>
