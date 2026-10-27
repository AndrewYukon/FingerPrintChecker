<?php
// Router for `php -S`: dumps what it received so the test can inspect the real wire format.
header('Content-Type: application/json');
header('Retry-After: 7');
echo json_encode([
    'method' => $_SERVER['REQUEST_METHOD'],
    'uri' => $_SERVER['REQUEST_URI'],
    'secret' => $_SERVER['HTTP_X_SECRET_KEY'] ?? null,
    'publishable' => $_SERVER['HTTP_X_PUBLISHABLE_KEY'] ?? null,
    'ua' => $_SERVER['HTTP_USER_AGENT'] ?? null,
    'ctype' => $_SERVER['CONTENT_TYPE'] ?? null,
    'body' => file_get_contents('php://input'),
]);
