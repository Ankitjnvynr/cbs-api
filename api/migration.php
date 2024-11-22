<?php
// Include the database connection
require_once '../_db.php';

try {
    // Create `users` table
    $sqlUsers = "CREATE TABLE IF NOT EXISTS users (
        id INT AUTO_INCREMENT PRIMARY KEY,
        username VARCHAR(100) NOT NULL UNIQUE,
        email VARCHAR(255) NOT NULL UNIQUE,
        password VARCHAR(255) NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP
    )";

    if ($conn->query($sqlUsers) === TRUE) {
        echo "Table `users` created successfully or already exists.\n";
    } else {
        throw new Exception("Error creating `users` table: " . $conn->error);
    }

    // Create `tokens` table
    $sqlTokens = "CREATE TABLE IF NOT EXISTS tokens (
        id INT AUTO_INCREMENT PRIMARY KEY,
        user_id INT NOT NULL,
        token TEXT NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    )";

    if ($conn->query($sqlTokens) === TRUE) {
        echo "Table `tokens` created successfully or already exists.\n";
    } else {
        throw new Exception("Error creating `tokens` table: " . $conn->error);
    }

} catch (Exception $e) {
    echo "Migration failed: " . $e->getMessage();
}

// Close the database connection
$conn->close();
?>
