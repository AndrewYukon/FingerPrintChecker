<?php
// Router for `php -S`: records each request's secret header (or "-") and answers {}.
file_put_contents((string) getenv('FP_LOG'), ($_SERVER['HTTP_X_SECRET_KEY'] ?? '-') . "\n", FILE_APPEND);
header('Content-Type: application/json');
echo '{}';
