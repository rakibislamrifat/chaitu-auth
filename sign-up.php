<?php
session_start();

require 'config.php';

// --- Create users table if not exists ---
$result = mysqli_query($conn, "SHOW TABLES LIKE 'users'");
if (mysqli_num_rows($result) == 0) {
    $create_table_sql = "
        CREATE TABLE users (
            id INT AUTO_INCREMENT PRIMARY KEY,
            first_name VARCHAR(100) NOT NULL,
            last_name VARCHAR(100) NOT NULL,
            dob DATE NOT NULL,
            address VARCHAR(255) NOT NULL,
            email VARCHAR(150) NOT NULL UNIQUE,
            phone VARCHAR(30) NOT NULL,
            username VARCHAR(100) NOT NULL UNIQUE,
            password_hash VARCHAR(255) NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ";
    if (!mysqli_query($conn, $create_table_sql)) {
        die("Error creating users table: " . mysqli_error($conn));
    }
}

// --- Add reset_token and reset_token_expiry columns if not exist ---
$result = mysqli_query($conn, "SHOW COLUMNS FROM users LIKE 'reset_token'");
if (mysqli_num_rows($result) == 0) {
    $alter_sql = "
        ALTER TABLE users
        ADD COLUMN reset_token VARCHAR(255) NULL,
        ADD COLUMN reset_token_expiry DATETIME NULL
    ";
    if (!mysqli_query($conn, $alter_sql)) {
        die("Error altering users table: " . mysqli_error($conn));
    }
}

// Use PHPMailer for sending email
use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';

$errors = [];

/**
 * Send OTP email via Gmail SMTP using PHPMailer
 */
function sendVerificationCode($email, $code) {
    $mail = new PHPMailer(true);
    try {
        $mail->isSMTP();
        $mail->Host       = 'smtp.gmail.com';
        $mail->SMTPAuth   = true;
        $mail->Username   = 'rakibislamrifat9@gmail.com';  // Your Gmail
        $mail->Password   = 'xnxnouvxhafizenv';           // Gmail App Password
        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
        $mail->Port       = 587;

        $mail->setFrom('rakibislamrifat9@gmail.com', 'The Velvet Reel');
        $mail->addAddress($email);

        $mail->isHTML(false);
        $mail->Subject = 'The Velvet Reel — Email Verification Code';
        $mail->Body = "Hello,\n\n"
            . "Thank you for registering at The Velvet Reel.\n"
            . "Your verification code is: $code\n\n"
            . "This code will expire in 5 minutes.\n\n"
            . "If you did not request this code, please ignore this email.\n\n"
            . "Best regards,\n"
            . "The Velvet Reel Team";

        $mail->send();
        return true;
    } catch (Exception $e) {
        error_log("Mailer Error: " . $mail->ErrorInfo);
        return false;
    }
}

// --- Handle form submission ---
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $first_name = trim($_POST['first_name'] ?? '');
    $last_name = trim($_POST['last_name'] ?? '');
    $dob = $_POST['dob'] ?? '';
    $address = trim($_POST['address'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $phone = trim($_POST['phone'] ?? '');
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $password_confirm = $_POST['password_confirm'] ?? '';
    $terms = isset($_POST['terms']);

    // Validate inputs
    if (!$first_name) $errors[] = "First name is required.";
    if (!$last_name) $errors[] = "Last name is required.";
    if ($dob) {
        $dobDate = new DateTime($dob);
        $today = new DateTime();
        $age = $today->diff($dobDate)->y;
        if ($age < 18) $errors[] = "You must be at least 18 years old to sign up.";
    } else {
        $errors[] = "Date of Birth is required.";
    }
    if (!$address) $errors[] = "Address is required.";
    if (!$email || !filter_var($email, FILTER_VALIDATE_EMAIL)) $errors[] = "Valid email is required.";
    if (!$phone) $errors[] = "Phone number is required.";
    if (!$username) $errors[] = "Username is required.";
    if (!$password) $errors[] = "Password is required.";
    if ($password !== $password_confirm) $errors[] = "Passwords do not match.";
    if (!$terms) $errors[] = "You must accept the terms and conditions.";

    // Check if username or email already exists
    if (empty($errors)) {
        $stmt = mysqli_prepare($conn, "SELECT COUNT(*) FROM users WHERE email = ? OR username = ?");
        mysqli_stmt_bind_param($stmt, "ss", $email, $username);
        mysqli_stmt_execute($stmt);
        mysqli_stmt_bind_result($stmt, $count);
        mysqli_stmt_fetch($stmt);
        mysqli_stmt_close($stmt);

        if ($count > 0) {
            $errors[] = "Username or email already taken.";
        }
    }

    // If no errors, generate OTP and save session data, send email
    if (empty($errors)) {
        $otp = random_int(100000, 999999);
        $_SESSION['pending_signup'] = [
            'first_name' => $first_name,
            'last_name' => $last_name,
            'dob' => $dob,
            'address' => $address,
            'email' => $email,
            'phone' => $phone,
            'username' => $username,
            'password_hash' => password_hash($password, PASSWORD_DEFAULT),
        ];
        $_SESSION['email_to_verify'] = $email;
        $_SESSION['email_otp'] = (string)$otp;
        $_SESSION['otp_expiry'] = time() + 300; // expires in 5 minutes

        if (sendVerificationCode($email, $otp)) {
            header('Location: verify-email.php');
            exit;
        } else {
            $errors[] = "Failed to send OTP email. Please try again.";
        }
    }
}
?>

<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8" />
<title>Sign Up - The Velvet Reel</title>
<style>
.error-messages { color: red; }
label { display: block; margin-top: 10px; }
</style>
</head>
<body>

<h2>Create an Account</h2>

<?php if ($errors): ?>
    <div class="error-messages">
        <ul>
            <?php foreach ($errors as $err): ?>
                <li><?= htmlspecialchars($err) ?></li>
            <?php endforeach; ?>
        </ul>
    </div>
<?php endif; ?>

<form method="POST" action="sign-up.php" novalidate>
    <label>First Name:
        <input type="text" name="first_name" value="<?= htmlspecialchars($_POST['first_name'] ?? '') ?>" required />
    </label>

    <label>Last Name:
        <input type="text" name="last_name" value="<?= htmlspecialchars($_POST['last_name'] ?? '') ?>" required />
    </label>

    <label>Date of Birth:
        <input type="date" name="dob" value="<?= htmlspecialchars($_POST['dob'] ?? '') ?>" required />
    </label>

    <label>Address:
        <input type="text" name="address" value="<?= htmlspecialchars($_POST['address'] ?? '') ?>" required />
    </label>

    <label>Email:
        <input type="email" name="email" value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" required />
    </label>

    <label>Phone Number:
        <input type="tel" name="phone" value="<?= htmlspecialchars($_POST['phone'] ?? '') ?>" required />
    </label>

    <label>Username:
        <input type="text" name="username" value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" required />
    </label>

    <label>Password:
        <input type="password" name="password" required />
    </label>

    <label>Confirm Password:
        <input type="password" name="password_confirm" required />
    </label>

    <label>
        <input type="checkbox" name="terms" <?= isset($_POST['terms']) ? 'checked' : '' ?> />
        I accept the <a href="terms.html" target="_blank">terms and conditions</a>.
    </label>

    <br/>
    <button type="submit">Sign Up</button>
</form>

</body>
</html>
