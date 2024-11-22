<?php
// Set response headers
header('Content-Type: application/json');

// Allow only POST requests
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405); // Method Not Allowed
    echo json_encode(['status' => 'error', 'message' => 'Invalid request method. Only POST is allowed.']);
    exit;
}

// Define the upload directory
$uploadDir = 'uploads/';
$response = ['status' => 'error'];

// Check if the file is uploaded
if (isset($_FILES['file'])) {
    $file = $_FILES['file'];
    $originalName = $file['name'];

    // Check for upload errors
    if ($file['error'] !== UPLOAD_ERR_OK) {
        echo json_encode(['status' => 'error', 'message' => 'File upload error.']);
        exit;
    }

    // Sanitize the file name (remove special characters)
    $sanitizedFileName = preg_replace("/[^a-zA-Z0-9.\-_]/", "", $originalName);

    // Get the file extension
    $fileExtension = pathinfo($sanitizedFileName, PATHINFO_EXTENSION);

    // Validate allowed file types (optional, adjust extensions as needed)
    $allowedExtensions = ['jpg', 'jpeg', 'png', 'pdf'];
    if (!in_array(strtolower($fileExtension), $allowedExtensions)) {
        echo json_encode(['status' => 'error', 'message' => 'Invalid file type. Allowed types: ' . implode(', ', $allowedExtensions)]);
        exit;
    }

    // Validate file size (optional, limit to 5MB)
    $maxFileSize = 5 * 1024 * 1024; // 5MB
    if ($file['size'] > $maxFileSize) {
        echo json_encode(['status' => 'error', 'message' => 'File size exceeds the maximum limit of 5MB.']);
        exit;
    }

    // Generate a unique name for the file
    $uniqueFileName = uniqid('file_', true) . '.' . $fileExtension;

    // Ensure the upload directory exists
    if (!is_dir($uploadDir)) {
        mkdir($uploadDir, 0755, true);
    }

    // Move the file to the upload directory
    $targetFilePath = $uploadDir . $uniqueFileName;
    if (move_uploaded_file($file['tmp_name'], $targetFilePath)) {
        $response = [
            'status' => 'success',
            'newFileName' => $uniqueFileName, // Return only the new file name
        ];
    } else {
        $response['message'] = 'Failed to move the uploaded file.';
    }
} else {
    $response['message'] = 'No file was uploaded. Please include a file parameter named "file".';
}

// Return the JSON response
echo json_encode($response);
?>