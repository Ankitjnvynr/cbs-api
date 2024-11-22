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

// Function to generate a token
function generateToken($userId) {
    return hash('sha256', $userId . time() . rand());
}

// Handle user operations
if ($method === 'POST' && isset($data['action'])) {
    $action = $data['action'];
    
    switch ($action) {
        // Other actions (create, update_password, delete) remain the same...

        case 'login': // Check user login and generate token
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
                    // Generate a token
                    $token = generateToken($user['id']);

                    // Store the token in the database
                    $stmtToken = $conn->prepare("INSERT INTO tokens (user_id, token) VALUES (?, ?)");
                    $stmtToken->bind_param('is', $user['id'], $token);

                    if ($stmtToken->execute()) {
                        // Remove the password field before sending response
                        unset($user['password']);
                        $user['token'] = $token;
                        sendResponse('success', 'Login successful.', $user);
                    } else {
                        sendResponse('error', 'Error storing token.', $conn->error);
                    }
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
