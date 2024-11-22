<?php
// Include the database connection
require_once '../_db.php';

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

            $hashedPassword = password_hash($password, PASSWORD_BCRYPT);
            $stmt = $conn->prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)");
            $stmt->bind_param('sss', $username, $email, $hashedPassword);

            if ($stmt->execute()) {
                sendResponse('success', 'User created successfully.');
            } else {
                sendResponse('error', 'Error creating user.', $conn->error);
            }
            break;

        case 'update_password': // Update user password
            $email = $data['email'] ?? null;
            $newPassword = $data['new_password'] ?? null;

            if (!$email || !$newPassword) {
                sendResponse('error', 'Missing required fields: email or new_password.');
            }

            $hashedPassword = password_hash($newPassword, PASSWORD_BCRYPT);
            $stmt = $conn->prepare("UPDATE users SET password = ? WHERE email = ?");
            $stmt->bind_param('ss', $hashedPassword, $email);

            if ($stmt->execute() && $stmt->affected_rows > 0) {
                sendResponse('success', 'Password updated successfully.');
            } else {
                sendResponse('error', 'Error updating password or user not found.', $conn->error);
            }
            break;

        case 'delete': // Delete a user
            $email = $data['email'] ?? null;

            if (!$email) {
                sendResponse('error', 'Missing required field: email.');
            }

            $stmt = $conn->prepare("DELETE FROM users WHERE email = ?");
            $stmt->bind_param('s', $email);

            if ($stmt->execute() && $stmt->affected_rows > 0) {
                sendResponse('success', 'User deleted successfully.');
            } else {
                sendResponse('error', 'Error deleting user or user not found.', $conn->error);
            }
            break;

        case 'login': // Check user login
            $email = $data['email'] ?? null;
            $password = $data['password'] ?? null;

            if (!$email || !$password) {
                sendResponse('error', 'Missing required fields: email or password.');
            }

            $stmt = $conn->prepare("SELECT id, username, email, password, created_at, updated_at FROM users WHERE email = ?");
            $stmt->bind_param('s', $email);
            $stmt->execute();
            $result = $stmt->get_result();

            if ($result->num_rows > 0) {
                $user = $result->fetch_assoc();

                // Verify the password
                if (password_verify($password, $user['password'])) {
                    // Remove the password field before sending response
                    unset($user['password']);
                    sendResponse('success', 'Login successful.', $user);
                } else {
                    sendResponse('error', 'Invalid email or password.');
                }
            } else {
                sendResponse('error', 'Invalid email or password.');
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