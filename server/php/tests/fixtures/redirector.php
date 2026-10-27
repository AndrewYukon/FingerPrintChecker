<?php
// Router for `php -S`: answers every request with a redirect to the target server.
http_response_code((int) getenv('FP_CODE'));
header('Location: http://127.0.0.1:' . getenv('FP_TARGET_PORT') . '/x');
