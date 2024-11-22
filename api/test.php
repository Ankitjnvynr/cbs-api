<?php
include '../_db.php';
// Set the response content type to JSON
header('Content-Type: application/json');

// Get the request method
$requestMethod = $_SERVER['REQUEST_METHOD'];

// Prepare the response
$response = [
    'status' => 'success',
    'request_method' => $requestMethod,
    'message' => "The request method is the $requestMethod."
];

// Send the response as JSON
echo json_encode($response);
?>
