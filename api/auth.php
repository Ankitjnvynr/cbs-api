<?php
// Include the database connection
require_once '../_db.php';

// Set CORS headers
$allowedOrigins = ['http://localhost:3000', 'https://yourdomain.com'];

if (isset($_SERVER['HTTP_ORIGIN']) && in_array($_SERVER['HTTP_ORIGIN'], $allowedOrigins)) {
    header('Access-Control-Allow-Origin: ' . $_SERVER['HTTP_ORIGIN']);
} else {
    header('Access-Control-Allow-Origin: https://yourdomain.com'); // Default to your production domain
}

header('Access-Control-Allow-Methods: GET, POST, OPTIONS');
header('Access-Control-Allow-Headers: Content-Type, Authorization');

// Handle preflight requests
if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
    http_response_code(200);
    exit;
}

// Set headers for JSON response
header('Content-Type: application/json');

// Fetch the request method and input data
$method = $_SERVER['REQUEST_METHOD'];
$data = json_decode(file_get_contents('php://input'), true);

// Check if data is provided
if (!$data) {
    echo json_encode(['status' => 'error', 'message' => 'No input data provided.']);
    exit;
}

// Function to send JSON responses
function sendResponse($status, $message, $data = null) {
    echo json_encode(['status' => $status, 'message' => $message, 'data' => $data]);
    exit;
}

// Function to generate a new token
function generateToken($userId) {
    return hash('sha256', $userId . time() . rand());
}

// Function to check if an existing token is still valid
function isTokenExpired($createdTime) {
    $currentTime = time();
    $tokenTime = strtotime($createdTime);
    $expirationTime = 7 * 24 * 60 * 60; // 7 days in seconds
    return ($currentTime - $tokenTime) > $expirationTime;
}

// Handle user operations
if ($method === 'POST' && isset($data['action'])) {
    $action = $data['action'];

    switch ($action) {
        case 'create': // Create a new user
            $username = $data['username'] ?? null;
            $email = $data['email'] ?? null;
            $password = $data['password'] ?? null;

            if (!$username || !$email || !$password) {
                sendResponse('error', 'Missing required fields: username, email, or password.');
            }

            // Hash the password
            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);

            // Insert user into the database
            $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param('sss', $username, $email, $hashedPassword);

            if ($stmt->execute()) {
                sendResponse('success', 'User created successfully.');
            } else {
                sendResponse('error', 'Error creating user.');
            }
            break;

        case 'login': // Check user login and manage token
            $email = $data['email'] ?? null;
            $password = $data['password'] ?? null;

            if (!$email || !$password) {
                sendResponse('error', 'Missing required fields: email or password.');
            }

            $stmt = $conn->prepare("SELECT id, username, email, password FROM users WHERE email = ?");
            $stmt->bind_param('s', $email);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $user = $result->fetch_assoc();

                // Verify the password
                if (password_verify($password, $user['password'])) {
                    $userId = $user['id'];

                    // Check if a valid token exists
                    $stmtToken = $conn->prepare("SELECT token, created_at FROM tokens WHERE user_id = ? ORDER BY created_at DESC LIMIT 1");
                    $stmtToken->bind_param('i', $userId);
                    $stmtToken->execute();
                    $tokenResult = $stmtToken->get_result();

                    if ($tokenResult->num_rows > 0) {
                        $existingToken = $tokenResult->fetch_assoc();
                        if (!isTokenExpired($existingToken['created_at'])) {
                            $token = $existingToken['token'];
                        } else {
                            $token = generateToken($userId);
                            $stmtInsertToken = $conn->prepare("INSERT INTO tokens (user_id, token) VALUES (?, ?)");
                            $stmtInsertToken->bind_param('is', $userId, $token);
                            $stmtInsertToken->execute();
                        }
                    } else {
                        $token = generateToken($userId);
                        $stmtInsertToken = $conn->prepare("INSERT INTO tokens (user_id, token) VALUES (?, ?)");
                        $stmtInsertToken->bind_param('is', $userId, $token);
                        $stmtInsertToken->execute();
                    }

                    unset($user['password']);
                    $user['token'] = $token;
                    sendResponse('success', 'Login successful.', $user);
                } else {
                    sendResponse('error', 'Invalid email or password.');
                }
            } else {
                sendResponse('error', 'Invalid email or password.');
            }
            break;

        case 'update_password': // Update user password
            $userId = $data['user_id'] ?? null;
            $oldPassword = $data['old_password'] ?? null;
            $newPassword = $data['new_password'] ?? null;

            if (!$userId || !$oldPassword || !$newPassword) {
                sendResponse('error', 'Missing required fields: user_id, old_password, or new_password.');
            }

            $stmt = $conn->prepare("SELECT password FROM users WHERE id = ?");
            $stmt->bind_param('i', $userId);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $user = $result->fetch_assoc();

                // Verify the old password
                if (password_verify($oldPassword, $user['password'])) {
                    $hashedNewPassword = password_hash($newPassword, PASSWORD_BCRYPT);

                    // Update the password
                    $stmtUpdate = $conn->prepare("UPDATE users SET password = ? WHERE id = ?");
                    $stmtUpdate->bind_param('si', $hashedNewPassword, $userId);

                    if ($stmtUpdate->execute()) {
                        sendResponse('success', 'Password updated successfully.');
                    } else {
                        sendResponse('error', 'Error updating password.');
                    }
                } else {
                    sendResponse('error', 'Invalid old password.');
                }
            } else {
                sendResponse('error', 'User not found.');
            }
            break;

        case 'delete': // Delete a user
            $userId = $data['user_id'] ?? null;

            if (!$userId) {
                sendResponse('error', 'Missing required field: user_id.');
            }

            $stmt = $conn->prepare("DELETE FROM users WHERE id = ?");
            $stmt->bind_param('i', $userId);

            if ($stmt->execute()) {
                sendResponse('success', 'User deleted successfully.');
            } else {
                sendResponse('error', 'Error deleting user.');
            }
            break;

        default:
            sendResponse('error', 'Invalid action provided.');
    }
} else {
    sendResponse('error', 'Invalid request method or missing action.');
}

// Close the database connection
$conn->close();
?>