<?php
session_start();
require 'config.php';

$errors = [];

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    if (!$email) $errors[] = "Email is required.";
    if (!$password) $errors[] = "Password is required.";

    if (empty($errors)) {
        // Prepare statement to select user by email only
        $stmt = mysqli_prepare($conn, "SELECT username, password_hash FROM users WHERE email = ?");
        mysqli_stmt_bind_param($stmt, "s", $email);
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
                $errors[] = "Invalid email or password.";
            }
        } else {
            $errors[] = "Invalid email or password.";
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
    <label>Email: <input type="email" name="email" required value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" /></label><br/>
    <label>Password: <input type="password" name="password" required /></label><br/>
    <button type="submit" name="submit">Sign In</button>
</form>
<p><a href="forgot-password.php">Forgot Password?</a></p>
</body>
</html>
