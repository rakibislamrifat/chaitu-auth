<?php
session_start();
require 'config.php';

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if (!$username) $errors[] = "Username or email required.";
    if (!$password) $errors[] = "Password required.";

    if (empty($errors)) {
        // Prepare statement to select user by username or email
        $stmt = mysqli_prepare($conn, "SELECT username, password_hash FROM users WHERE username = ? OR email = ?");
        mysqli_stmt_bind_param($stmt, "ss", $username, $username);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_store_result($stmt);

        if (mysqli_stmt_num_rows($stmt) === 1) {
            mysqli_stmt_bind_result($stmt, $db_username, $db_password_hash);
            mysqli_stmt_fetch($stmt);

            if (password_verify($password, $db_password_hash)) {
                $_SESSION['user'] = $db_username;
                header('Location: index.php');
                exit;
            } else {
                $errors[] = "Invalid username/email or password.";
            }
        } else {
            $errors[] = "Invalid username/email or password.";
        }
        mysqli_stmt_close($stmt);
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Sign In</title>
    <link rel="stylesheet" href="style.css" />
</head>
<body>
<h2>Sign In</h2>

<?php if (!empty($errors)): ?>
    <div class="error-messages">
        <ul>
            <?php foreach($errors as $err): ?>
                <li><?= htmlspecialchars($err) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<form method="POST" action="sign-in.php" novalidate>
    <label>Username or Email: <input type="text" name="username" required value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" /></label><br/>
    <label>Password: <input type="password" name="password" required /></label><br/>
    <button type="submit" name="submit">Sign In</button>
</form>
<p><a href="forgot_password.php">Forgot Password?</a></p>
</body>
</html>
