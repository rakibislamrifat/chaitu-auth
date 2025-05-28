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
<meta name="viewport" content="width=device-width, initial-scale=1.0" />
<title>Sign Up - The Velvet Reel</title>
<link href="https://fonts.googleapis.com/css2?family=Playfair+Display:wght@400;600;700&family=Inter:wght@300;400;500;600&display=swap" rel="stylesheet">
<style>
* {
    margin: 0;
    padding: 0;
    box-sizing: border-box;
}

.chaitu-body {
    font-family: 'Inter', sans-serif;
    background: linear-gradient(135deg, #1a1a1a 0%, #2d2d2d 100%);
    min-height: 100vh;
    color: #ffffff;
    padding: 20px;
}

.chaitu-container {
    max-width: 600px;
    margin: 0 auto;
    padding: 40px;
    background: rgba(255, 255, 255, 0.05);
    backdrop-filter: blur(10px);
    border-radius: 20px;
    border: 1px solid rgba(255, 255, 255, 0.1);
    box-shadow: 0 20px 40px rgba(0, 0, 0, 0.3);
}

.chaitu-header {
    text-align: center;
    margin-bottom: 40px;
}

.chaitu-brand {
    font-family: 'Playfair Display', serif;
    font-size: 2.5rem;
    font-weight: 600;
    background: linear-gradient(135deg, #ffffff 0%, #f0f0f0 100%);
    background-clip: text;
    -webkit-background-clip: text;
    -webkit-text-fill-color: transparent;
    margin-bottom: 10px;
    letter-spacing: 1px;
}

.chaitu-subtitle {
    font-size: 1.1rem;
    color: #cccccc;
    font-weight: 300;
    margin-bottom: 10px;
}

.chaitu-title {
    font-size: 1.8rem;
    font-weight: 600;
    color: #ffffff;
    margin-top: 20px;
}

.chaitu-error-messages {
    background: rgba(220, 53, 69, 0.15);
    border: 1px solid rgba(220, 53, 69, 0.3);
    border-radius: 10px;
    padding: 20px;
    margin-bottom: 30px;
    backdrop-filter: blur(10px);
}

.chaitu-error-messages ul {
    list-style: none;
}

.chaitu-error-messages li {
    color: #ff6b7a;
    margin-bottom: 8px;
    font-size: 0.95rem;
    padding-left: 20px;
    position: relative;
}

.chaitu-error-messages li:before {
    content: "⚠";
    position: absolute;
    left: 0;
    color: #dc3545;
}

.chaitu-form {
    display: grid;
    gap: 25px;
}

.chaitu-form-row {
    display: grid;
    grid-template-columns: 1fr 1fr;
    gap: 20px;
}

.chaitu-form-group {
    display: flex;
    flex-direction: column;
}

.chaitu-label {
    font-size: 0.95rem;
    font-weight: 500;
    color: #e0e0e0;
    margin-bottom: 8px;
    letter-spacing: 0.3px;
}

.chaitu-input {
    background: rgba(255, 255, 255, 0.08);
    border: 1px solid rgba(255, 255, 255, 0.15);
    border-radius: 12px;
    padding: 15px 18px;
    font-size: 1rem;
    color: #ffffff;
    transition: all 0.3s ease;
    font-family: 'Inter', sans-serif;
}

.chaitu-input::placeholder {
    color: #999999;
}

.chaitu-input:focus {
    outline: none;
    border-color: #dc3545;
    background: rgba(255, 255, 255, 0.12);
    box-shadow: 0 0 0 3px rgba(220, 53, 69, 0.1);
    transform: translateY(-1px);
}

.chaitu-input:hover {
    border-color: rgba(255, 255, 255, 0.25);
    background: rgba(255, 255, 255, 0.1);
}

.chaitu-checkbox-group {
    display: flex;
    align-items: flex-start;
    gap: 12px;
    margin-top: 10px;
}

.chaitu-checkbox {
    width: 20px;
    height: 20px;
    accent-color: #dc3545;
    cursor: pointer;
    margin-top: 2px;
}

.chaitu-checkbox-label {
    color: #cccccc;
    font-size: 0.95rem;
    line-height: 1.5;
    cursor: pointer;
    flex: 1;
}

.chaitu-checkbox-label a {
    color: #dc3545;
    text-decoration: none;
    font-weight: 500;
    transition: color 0.3s ease;
}

.chaitu-checkbox-label a:hover {
    color: #ff4757;
    text-decoration: underline;
}

.chaitu-submit-btn {
    background: linear-gradient(135deg, #dc3545 0%, #c82333 100%);
    color: white;
    border: none;
    border-radius: 12px;
    padding: 18px 40px;
    font-size: 1.1rem;
    font-weight: 600;
    cursor: pointer;
    transition: all 0.3s ease;
    margin-top: 20px;
    font-family: 'Inter', sans-serif;
    letter-spacing: 0.5px;
    text-transform: uppercase;
    position: relative;
    overflow: hidden;
}

.chaitu-submit-btn:before {
    content: '';
    position: absolute;
    top: 0;
    left: -100%;
    width: 100%;
    height: 100%;
    background: linear-gradient(90deg, transparent, rgba(255, 255, 255, 0.2), transparent);
    transition: left 0.5s;
}

.chaitu-submit-btn:hover:before {
    left: 100%;
}

.chaitu-submit-btn:hover {
    transform: translateY(-2px);
    box-shadow: 0 8px 25px rgba(220, 53, 69, 0.4);
    background: linear-gradient(135deg, #e74c3c 0%, #c0392b 100%);
}

.chaitu-submit-btn:active {
    transform: translateY(0);
}

/* Responsive Design */
@media (max-width: 768px) {
    .chaitu-container {
        margin: 10px;
        padding: 30px 25px;
    }
    
    .chaitu-brand {
        font-size: 2rem;
    }
    
    .chaitu-form-row {
        grid-template-columns: 1fr;
        gap: 15px;
    }
    
    .chaitu-input {
        padding: 12px 15px;
    }
    
    .chaitu-submit-btn {
        padding: 15px 30px;
        font-size: 1rem;
    }
}

@media (max-width: 480px) {
    .chaitu-container {
        margin: 5px;
        padding: 25px 20px;
    }
    
    .chaitu-brand {
        font-size: 1.8rem;
    }
    
    .chaitu-title {
        font-size: 1.5rem;
    }
}

/* Animation for form elements */
.chaitu-form-group {
    animation: fadeInUp 0.6s ease forwards;
    opacity: 0;
    transform: translateY(20px);
}

.chaitu-form-group:nth-child(1) { animation-delay: 0.1s; }
.chaitu-form-group:nth-child(2) { animation-delay: 0.2s; }
.chaitu-form-group:nth-child(3) { animation-delay: 0.3s; }
.chaitu-form-group:nth-child(4) { animation-delay: 0.4s; }
.chaitu-form-group:nth-child(5) { animation-delay: 0.5s; }

@keyframes fadeInUp {
    to {
        opacity: 1;
        transform: translateY(0);
    }
}

/* Loading state for button */
.chaitu-submit-btn:disabled {
    opacity: 0.7;
    cursor: not-allowed;
    transform: none;
}

/* Custom date picker styling */
.chaitu-input[type="date"] {
    color-scheme: dark;
}

.chaitu-input[type="date"]::-webkit-calendar-picker-indicator {
    filter: invert(1);
    cursor: pointer;
}
</style>
</head>
<body class="chaitu-body">

<div class="chaitu-container">
    <div class="chaitu-header">
        <h1 class="chaitu-brand">The Velvet Reel</h1>
        <p class="chaitu-subtitle">Connecting visionary projects with extraordinary talents</p>
        <h2 class="chaitu-title">Create Your Account</h2>
    </div>

    <?php if ($errors): ?>
        <div class="chaitu-error-messages">
            <ul>
                <?php foreach ($errors as $err): ?>
                    <li><?= htmlspecialchars($err) ?></li>
                <?php endforeach; ?>
            </ul>
        </div>
    <?php endif; ?>

    <form method="POST" action="sign-up.php" novalidate class="chaitu-form">
        <div class="chaitu-form-row">
            <div class="chaitu-form-group">
                <label class="chaitu-label">First Name</label>
                <input type="text" name="first_name" class="chaitu-input" 
                       value="<?= htmlspecialchars($_POST['first_name'] ?? '') ?>" 
                       placeholder="Enter your first name" required />
            </div>

            <div class="chaitu-form-group">
                <label class="chaitu-label">Last Name</label>
                <input type="text" name="last_name" class="chaitu-input" 
                       value="<?= htmlspecialchars($_POST['last_name'] ?? '') ?>" 
                       placeholder="Enter your last name" required />
            </div>
        </div>

        <div class="chaitu-form-group">
            <label class="chaitu-label">Date of Birth</label>
            <input type="date" name="dob" class="chaitu-input" 
                   value="<?= htmlspecialchars($_POST['dob'] ?? '') ?>" required />
        </div>

        <div class="chaitu-form-group">
            <label class="chaitu-label">Address</label>
            <input type="text" name="address" class="chaitu-input" 
                   value="<?= htmlspecialchars($_POST['address'] ?? '') ?>" 
                   placeholder="Enter your full address" required />
        </div>

        <div class="chaitu-form-row">
            <div class="chaitu-form-group">
                <label class="chaitu-label">Email Address</label>
                <input type="email" name="email" class="chaitu-input" 
                       value="<?= htmlspecialchars($_POST['email'] ?? '') ?>" 
                       placeholder="your.email@example.com" required />
            </div>

            <div class="chaitu-form-group">
                <label class="chaitu-label">Phone Number</label>
                <input type="tel" name="phone" class="chaitu-input" 
                       value="<?= htmlspecialchars($_POST['phone'] ?? '') ?>" 
                       placeholder="+1 (555) 123-4567" required />
            </div>
        </div>

        <div class="chaitu-form-group">
            <label class="chaitu-label">Username</label>
            <input type="text" name="username" class="chaitu-input" 
                   value="<?= htmlspecialchars($_POST['username'] ?? '') ?>" 
                   placeholder="Choose a unique username" required />
        </div>

        <div class="chaitu-form-row">
            <div class="chaitu-form-group">
                <label class="chaitu-label">Password</label>
                <input type="password" name="password" class="chaitu-input" 
                       placeholder="Create a strong password" required />
            </div>

            <div class="chaitu-form-group">
                <label class="chaitu-label">Confirm Password</label>
                <input type="password" name="password_confirm" class="chaitu-input" 
                       placeholder="Confirm your password" required />
            </div>
        </div>

        <div class="chaitu-checkbox-group">
            <input type="checkbox" name="terms" id="terms" class="chaitu-checkbox" 
                   <?= isset($_POST['terms']) ? 'checked' : '' ?> />
            <label for="terms" class="chaitu-checkbox-label">
                I accept the <a href="terms.html" target="_blank">Terms and Conditions</a> 
                and acknowledge that I have read the Privacy Policy.
            </label>
        </div>

        <button type="submit" class="chaitu-submit-btn">Create Account</button>
    </form>
</div>

</body>
</html>