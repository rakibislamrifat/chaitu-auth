<?php
session_start();
require 'config.php';

$errors = [];

// Check if user table exists, create if not
$result = mysqli_query($conn, "SHOW TABLES LIKE 'users'");
if (mysqli_num_rows($result) == 0) {
    $create_table_sql = "CREATE TABLE users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        first_name VARCHAR(50) NOT NULL,
        last_name VARCHAR(50) NOT NULL,
        dob DATE NOT NULL,
        address VARCHAR(255) NOT NULL,
        email VARCHAR(100) NOT NULL UNIQUE,
        phone VARCHAR(20) NOT NULL,
        username VARCHAR(50) NOT NULL UNIQUE,
        password_hash VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    )";
    if (!mysqli_query($conn, $create_table_sql)) {
        die("Error creating users table: " . mysqli_error($conn));
    }
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // Sanitize input
    $first_name = trim($_POST['first_name'] ?? '');
    $last_name = trim($_POST['last_name'] ?? '');
    $dob = $_POST['dob'] ?? '';
    $address = trim($_POST['address'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $phone = trim($_POST['phone'] ?? '');
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $password_confirm = $_POST['password_confirm'] ?? '';
    $terms = isset($_POST['terms']) ? true : false;

    // Validation
    if (!$first_name) $errors[] = "First name is required.";
    if (!$last_name) $errors[] = "Last name is required.";
    if (!$dob) $errors[] = "Date of birth is required.";
    if (!$address) $errors[] = "Address is required.";
    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = "Valid email is required.";
    if (!$phone) $errors[] = "Phone number is required.";
    if (!$username) $errors[] = "Username is required.";
    if (!$password) $errors[] = "Password is required.";
    if ($password !== $password_confirm) $errors[] = "Passwords do not match.";
    if (!$terms) $errors[] = "You must accept the terms and conditions.";

    // Check if username or email exists
    if (empty($errors)) {
        $stmt = mysqli_prepare($conn, "SELECT COUNT(*) FROM users WHERE username = ? OR email = ?");
        mysqli_stmt_bind_param($stmt, "ss", $username, $email);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $count);
        mysqli_stmt_fetch($stmt);
        mysqli_stmt_close($stmt);

        if ($count > 0) {
            $errors[] = "Username or email already taken.";
        }
    }

    // Insert new user if no errors
    if (empty($errors)) {
        $password_hash = password_hash($password, PASSWORD_DEFAULT);

        $stmt = mysqli_prepare($conn, "INSERT INTO users (first_name, last_name, dob, address, email, phone, username, password_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)");
        mysqli_stmt_bind_param($stmt, "ssssssss", $first_name, $last_name, $dob, $address, $email, $phone, $username, $password_hash);
        $exec = mysqli_stmt_execute($stmt);
        mysqli_stmt_close($stmt);

        if ($exec) {
            $_SESSION['user'] = $username;
            header('Location: index.php');
            exit;
        } else {
            $errors[] = "Database insert error: " . mysqli_error($conn);
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Sign Up</title>
    <link rel="stylesheet" href="style.css" />
</head>
<body>
<h2>Create an Account</h2>

<?php if (!empty($errors)): ?>
    <div class="error-messages">
        <ul>
            <?php foreach ($errors as $err): ?>
                <li><?= htmlspecialchars($err) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<form method="POST" action="sign-up.php" novalidate>
    <label>First Name: <input type="text" name="first_name" required value="<?= htmlspecialchars($_POST['first_name'] ?? '') ?>" /></label><br/>
    <label>Last Name: <input type="text" name="last_name" required value="<?= htmlspecialchars($_POST['last_name'] ?? '') ?>" /></label><br/>
    <label>Date of Birth: <input type="date" name="dob" required value="<?= htmlspecialchars($_POST['dob'] ?? '') ?>" /></label><br/>
    <label>Address: <input type="text" name="address" required value="<?= htmlspecialchars($_POST['address'] ?? '') ?>" /></label><br/>
    <label>Email: <input type="email" name="email" required value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" /></label><br/>
    <label>Phone Number: <input type="tel" name="phone" required value="<?= htmlspecialchars($_POST['phone'] ?? '') ?>" /></label><br/>
    <label>Username: <input type="text" name="username" required value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" /></label><br/>
    <label>Password: <input type="password" name="password" required /></label><br/>
    <label>Confirm Password: <input type="password" name="password_confirm" required /></label><br/>
    <label>
        <input type="checkbox" name="terms" <?= isset($_POST['terms']) ? 'checked' : '' ?> />
        I accept the <a href="terms.html" target="_blank">terms and conditions</a>.
    </label><br/>
    <button type="submit" name="submit">Sign Up</button>
</form>
</body>
</html>
