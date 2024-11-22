<?php
header('Content-Type: application/json');
// Function to parse .env file
function loadEnv($filePath) {
    if (!file_exists($filePath)) {
        echo json_encode([
            'status' => 'error',
            'message' => '.env file not found.'
        ]);
        exit;
    }
    $env = parse_ini_file($filePath);
    if ($env === false) {
        echo json_encode([
            'status' => 'error',
            'message' => 'Unable to parse .env file.'
        ]);
        exit;
    }
    return $env;
}

try {
    // Load environment variables
    $env = loadEnv(__DIR__ . '/.env');

    // Database credentials from .env file
    $host = $env['DB_HOST'];
    $user = $env['DB_USER'];
    $password = $env['DB_PASSWORD'];
    $dbName = $env['DB_NAME'];
    $port = $env['DB_PORT'];

    // Establish database connection using mysqli
    $conn = new mysqli($host, $user, $password, $dbName, $port);

    // Check for connection errors
    if ($conn->connect_error) {
        throw new Exception("Connection failed: " . $conn->connect_error);
    }

    // Output success message (optional, can be removed in production)
     json_encode([
        'status' => 'success',
        'message' => 'Database connected successfully.'
    ]);

} catch (Exception $e) {
    // Return error in JSON format
    echo json_encode([
        'status' => 'error',
        'message' => $e->getMessage()
    ]);
    exit;
}
?>
