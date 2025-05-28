<?php
session_start();
require 'config.php';

$errors = [];
$success = "";

$token = $_GET['token'] ?? '';

if (!$token) {
    die("Invalid password reset link.");
}

// Check token validity
$stmt = mysqli_prepare($conn, "SELECT id, reset_token_expiry FROM users WHERE reset_token = ?");
mysqli_stmt_bind_param($stmt, "s", $token);
mysqli_stmt_execute($stmt);
mysqli_stmt_bind_result($stmt, $user_id, $expiry);
mysqli_stmt_fetch($stmt);
mysqli_stmt_close($stmt);

if (!$user_id || strtotime($expiry) < time()) {
    die("This password reset link is invalid or has expired.");
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $password = $_POST['password'] ?? '';
    $password_confirm = $_POST['password_confirm'] ?? '';

    if (!$password) $errors[] = "Password is required.";
    if ($password !== $password_confirm) $errors[] = "Passwords do not match.";

    if (empty($errors)) {
        $password_hash = password_hash($password, PASSWORD_DEFAULT);

        // Update password, clear reset token and expiry
        $stmt = mysqli_prepare($conn, "UPDATE users SET password_hash = ?, reset_token = NULL, reset_token_expiry = NULL WHERE id = ?");
        mysqli_stmt_bind_param($stmt, "si", $password_hash, $user_id);
        $exec = mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);

        if ($exec) {
            $success = "Password has been reset successfully. You can now <a href='sign-in.php'>login</a>.";
        } else {
            $errors[] = "Database error, please try again.";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head><title>Reset Password</title></head>
<body>
<h2>Reset Password</h2>

<?php if ($errors): ?>
<div style="color:red;">
    <ul>
        <?php foreach ($errors as $e) echo "<li>" . htmlspecialchars($e) . "</li>"; ?>
    </ul>
</div>
<?php endif; ?>

<?php if ($success): ?>
<div style="color:green;">
    <?= $success ?>
</div>
<?php else: ?>
<form method="POST" action="reset-password.php?token=<?= htmlspecialchars($token) ?>" novalidate>
    <label>New Password: <input type="password" name="password" required /></label><br/>
    <label>Confirm Password: <input type="password" name="password_confirm" required /></label><br/>
    <button type="submit">Reset Password</button>
</form>
<?php endif; ?>

</body>
</html>
