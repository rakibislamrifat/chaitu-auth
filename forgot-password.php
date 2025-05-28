<?php
session_start();
require 'config.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

require 'vendor/autoload.php';

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
            // Generate 6-digit OTP and expiry (e.g., 10 minutes)
            $otp = random_int(100000, 999999);
            $expiry = date("Y-m-d H:i:s", strtotime("+10 minutes"));

            // Save OTP and expiry in DB
            $stmt = mysqli_prepare($conn, "UPDATE users SET reset_token = ?, reset_token_expiry = ? WHERE id = ?");
            mysqli_stmt_bind_param($stmt, "ssi", $otp, $expiry, $user_id);
            mysqli_stmt_execute($stmt);
            mysqli_stmt_close($stmt);

            // Send OTP email
            $subject = "Your Password Reset OTP";
            $message = "Hello,\n\nYour password reset OTP code is: $otp\n\n"
                     . "This code will expire in 10 minutes.\n\n"
                     . "If you didn't request this, please ignore this email.";

            $mail = new PHPMailer(true);
            try {
                $mail->isSMTP();
                $mail->Host = 'smtp.gmail.com';
                $mail->SMTPAuth = true;
                $mail->Username   = 'rakibislamrifat9@gmail.com';       // Your Gmail
                $mail->Password   = 'xnxnouvxhafizenv';        // Your Gmail app password
                $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS;
                $mail->Port = 587;

                $mail->setFrom('rakibislamrifat9@gmail.com', 'The Velvet Reel');
                $mail->addAddress($email);

                $mail->Subject = $subject;
                $mail->Body = $message;

                $mail->send();
                $_SESSION['reset_email'] = $email; // store for verification step
                header('Location: verify-otp.php');
                exit;
            } catch (Exception $e) {
                $errors[] = "Could not send OTP email. Mailer Error: " . $mail->ErrorInfo;
            }
        } else {
            $errors[] = "No account found with that email address.";
        }
    }
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Forgot Password</title>
</head>
<body>
<h2>Forgot Password</h2>

<?php if ($errors): ?>
    <div style="color:red;">
        <ul>
            <?php foreach ($errors as $e) echo "<li>" . htmlspecialchars($e) . "</li>"; ?>
        </ul>
    </div>
<?php endif; ?>

<form method="POST" action="forgot-password.php" novalidate>
    <label>Email: <input type="email" name="email" required /></label><br/>
    <button type="submit">Send OTP</button>
</form>

</body>
</html>
