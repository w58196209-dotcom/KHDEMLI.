<?php

declare(strict_types=1);

ini_set('display_errors', '0');
error_reporting(E_ALL);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');

function respond(int $status, $payload = null): void
{
    http_response_code($status);
    if ($status !== 204) {
        echo json_encode($payload, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES | JSON_INVALID_UTF8_SUBSTITUTE);
    }
    exit;
}

function fail(int $status, string $message): void
{
    respond($status, ['error' => $message]);
}

function nowIso(): string
{
    return gmdate('Y-m-d\TH:i:s\Z');
}

function uuidV4(): string
{
    $bytes = random_bytes(16);
    $bytes[6] = chr((ord($bytes[6]) & 0x0f) | 0x40);
    $bytes[8] = chr((ord($bytes[8]) & 0x3f) | 0x80);
    $hex = bin2hex($bytes);
    return substr($hex, 0, 8) . '-' . substr($hex, 8, 4) . '-' . substr($hex, 12, 4) . '-'
        . substr($hex, 16, 4) . '-' . substr($hex, 20);
}

function stringLength(string $value): int
{
    if (function_exists('mb_strlen')) {
        return mb_strlen($value, 'UTF-8');
    }
    preg_match_all('/./us', $value, $matches);
    return count($matches[0]);
}

function readBody(): array
{
    $length = (int)($_SERVER['CONTENT_LENGTH'] ?? 0);
    if ($length > 32768) {
        fail(413, 'حجم الطلب أكبر من المسموح.');
    }
    $raw = file_get_contents('php://input');
    if ($raw === false || $raw === '') {
        return [];
    }
    if (strlen($raw) > 32768) {
        fail(413, 'حجم الطلب أكبر من المسموح.');
    }
    try {
        $body = json_decode($raw, true, 32, JSON_THROW_ON_ERROR);
    } catch (JsonException $error) {
        fail(400, 'بيانات الطلب غير صالحة.');
    }
    if (!is_array($body)) {
        fail(400, 'صيغة الطلب غير صالحة.');
    }
    return $body;
}

function requestMethod(): string
{
    return strtoupper($_SERVER['REQUEST_METHOD'] ?? 'GET');
}

function requestPath(): string
{
    $path = parse_url($_SERVER['REQUEST_URI'] ?? '/api', PHP_URL_PATH);
    if (!is_string($path)) {
        return '';
    }
    return preg_replace('~^/api(?:/|$)~', '', $path) ?? '';
}

function requestCookies(): array
{
    return $_COOKIE;
}

function requestUser(PDO $db): ?array
{
    $token = requestCookies()['khdemli_session'] ?? '';
    if (!is_string($token) || $token === '' || strlen($token) > 256) {
        return null;
    }
    $query = $db->prepare('
        SELECT u.id, u.first_name AS firstName, u.last_name AS lastName,
               CONCAT(u.first_name, " ", u.last_name) AS name, u.email,
               "all" AS accountType, u.phone, u.wilaya
        FROM sessions s JOIN users u ON u.id = s.user_id
        WHERE s.token_hash = ? AND s.expires_at > ?
        LIMIT 1
    ');
    $query->execute([hash('sha256', $token), (int)floor(microtime(true) * 1000)]);
    $user = $query->fetch(PDO::FETCH_ASSOC);
    if (!$user) {
        return null;
    }
    $user['id'] = (int)$user['id'];
    return $user;
}

function requireUser(PDO $db): array
{
    $user = requestUser($db);
    if (!$user) {
        fail(401, 'يلزم تسجيل الدخول للمتابعة.');
    }
    return $user;
}

function adminSession(PDO $db): ?string
{
    $token = requestCookies()['khdemli_admin'] ?? '';
    if (!is_string($token) || $token === '' || strlen($token) > 256) {
        return null;
    }
    $hash = hash('sha256', $token);
    $query = $db->prepare('SELECT token_hash FROM admin_sessions WHERE token_hash = ? AND expires_at > ?');
    $query->execute([$hash, (int)floor(microtime(true) * 1000)]);
    return $query->fetchColumn() ? $hash : null;
}

function requireAdmin(PDO $db): string
{
    $session = adminSession($db);
    if (!$session) {
        fail(401, 'سجّل دخول المشرف للمتابعة.');
    }
    return $session;
}

function setAuthCookie(string $name, string $token, string $sameSite = 'Lax'): void
{
    setcookie($name, $token, [
        'expires' => time() + 14 * 24 * 60 * 60,
        'path' => '/',
        'secure' => requestIsSecure(),
        'httponly' => true,
        'samesite' => $sameSite,
    ]);
}

function requestIsSecure(): bool
{
    return (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') === '443');
}

function clearAuthCookie(string $name, string $sameSite = 'Lax'): void
{
    setcookie($name, '', [
        'expires' => time() - 3600,
        'path' => '/',
        'secure' => requestIsSecure(),
        'httponly' => true,
        'samesite' => $sameSite,
    ]);
}

function createUserSession(PDO $db, int $userId): void
{
    $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
    $db->prepare('INSERT INTO sessions (token_hash, user_id, expires_at) VALUES (?, ?, ?)')
        ->execute([hash('sha256', $token), $userId, (int)floor(microtime(true) * 1000) + 14 * 24 * 60 * 60 * 1000]);
    setAuthCookie('khdemli_session', $token);
}

function recordAdminAction(PDO $db, string $action, string $resourceId = ''): void
{
    $db->prepare('INSERT INTO admin_audit_log (`action`, resource_id, created_at) VALUES (?, ?, ?)')
        ->execute([$action, $resourceId, nowIso()]);
}

function originMatchesRequest(): bool
{
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    if ($origin === '') {
        return true;
    }
    $parts = parse_url($origin);
    if (!is_array($parts) || empty($parts['scheme']) || empty($parts['host'])) {
        return false;
    }
    $scheme = (!empty($_SERVER['HTTPS']) && strtolower((string)$_SERVER['HTTPS']) !== 'off')
        || (($_SERVER['SERVER_PORT'] ?? '') === '443') ? 'https' : 'http';
    $originScheme = strtolower($parts['scheme']);
    $originPort = $parts['port'] ?? ($originScheme === 'https' ? 443 : 80);
    $requestPort = str_contains($_SERVER['HTTP_HOST'] ?? '', ':')
        ? (int)substr(strrchr($_SERVER['HTTP_HOST'], ':'), 1)
        : ($scheme === 'https' ? 443 : 80);
    $requestHost = strtolower(preg_replace('/:\d+$/', '', $_SERVER['HTTP_HOST'] ?? '') ?? '');
    return $originScheme === $scheme
        && strtolower($parts['host']) === $requestHost
        && (int)$originPort === $requestPort;
}

function loginIsLimited(PDO $db, string $kind, string $ip, string $secret): bool
{
    $ipHash = hash_hmac('sha256', $ip, $secret);
    $now = (int)floor(microtime(true) * 1000);
    $query = $db->prepare('SELECT started_at, attempt_count FROM login_attempts WHERE kind = ? AND ip_hash = ?');
    $query->execute([$kind, $ipHash]);
    $attempt = $query->fetch(PDO::FETCH_ASSOC);
    if (!$attempt || $now - (int)$attempt['started_at'] >= 15 * 60 * 1000) {
        $db->prepare('
            INSERT INTO login_attempts (kind, ip_hash, started_at, attempt_count) VALUES (?, ?, ?, 1)
            ON DUPLICATE KEY UPDATE started_at = VALUES(started_at), attempt_count = 1
        ')->execute([$kind, $ipHash, $now]);
        return false;
    }
    $db->prepare('UPDATE login_attempts SET attempt_count = LEAST(attempt_count + 1, 255) WHERE kind = ? AND ip_hash = ?')
        ->execute([$kind, $ipHash]);
    return (int)$attempt['attempt_count'] + 1 > 10;
}

function clearLoginLimit(PDO $db, string $kind, string $ip, string $secret): void
{
    $db->prepare('DELETE FROM login_attempts WHERE kind = ? AND ip_hash = ?')
        ->execute([$kind, hash_hmac('sha256', $ip, $secret)]);
}

function hasTwoWayConversation(PDO $db, int $reviewerId, int $providerId): bool
{
    $query = $db->prepare('
        SELECT 1
        FROM conversations c
        JOIN services s ON s.id = c.service_id
        WHERE c.requester_id = ? AND s.owner_id = ?
          AND EXISTS (SELECT 1 FROM messages m WHERE m.conversation_id = c.id AND m.sender_id = c.requester_id)
          AND EXISTS (SELECT 1 FROM messages m WHERE m.conversation_id = c.id AND m.sender_id = s.owner_id)
        LIMIT 1
    ');
    $query->execute([$reviewerId, $providerId]);
    return (bool)$query->fetchColumn();
}

function validPassword(string $password): bool
{
    $length = stringLength($password);
    return $length >= 8 && $length <= 128
        && preg_match('/[A-Za-z\x{0600}-\x{06FF}]/u', $password) === 1
        && preg_match('/[0-9]/', $password) === 1;
}

function newPasswordHash(string $password): string
{
    return password_hash(hash('sha256', $password), PASSWORD_DEFAULT);
}

function login(PDO $db, array $account, string $password): bool
{
    $stored = (string)$account['password_hash'];
    if (str_starts_with($stored, '$2y$') || str_starts_with($stored, '$argon2')) {
        return password_verify(hash('sha256', $password), $stored);
    }
    return false;
}

function run(PDO $db, array $config): void
{
    $method = requestMethod();
    $path = requestPath();
    $body = in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true) ? readBody() : [];
    if (in_array($method, ['POST', 'PUT', 'PATCH', 'DELETE'], true) && !originMatchesRequest()) {
        fail(403, 'مصدر الطلب غير مسموح.');
    }

    $db->prepare('DELETE FROM sessions WHERE expires_at <= ?')->execute([(int)floor(microtime(true) * 1000)]);
    $db->prepare('DELETE FROM admin_sessions WHERE expires_at <= ?')->execute([(int)floor(microtime(true) * 1000)]);
    $db->prepare('DELETE FROM migration_reset_tokens WHERE expires_at <= ?')->execute([(int)floor(microtime(true) * 1000)]);
    $db->prepare('DELETE FROM login_attempts WHERE started_at <= ?')
        ->execute([(int)floor(microtime(true) * 1000) - 24 * 60 * 60 * 1000]);

    if ($method === 'GET' && $path === 'bootstrap') {
        $user = requestUser($db);
        $services = $db->query('
            SELECT s.id, s.owner_id AS owner, CONCAT(u.first_name, " ", u.last_name) AS ownerName,
                   s.title, s.category, s.area, s.price, s.description, s.created_at AS createdAt
            FROM services s JOIN users u ON u.id = s.owner_id ORDER BY s.created_at DESC
        ')->fetchAll(PDO::FETCH_ASSOC);
        foreach ($services as &$service) {
            $service['owner'] = (int)$service['owner'];
            $service['price'] = (int)$service['price'];
        }
        unset($service);

        if ($user) {
            $query = $db->prepare('
                SELECT DISTINCT u.id, CONCAT(u.first_name, " ", u.last_name) AS name
                FROM users u
                WHERE u.id = ? OR u.id IN (SELECT owner_id FROM services)
                   OR u.id IN (
                       SELECT cp2.user_id FROM conversation_participants cp1
                       JOIN conversation_participants cp2 ON cp1.conversation_id = cp2.conversation_id
                       WHERE cp1.user_id = ?
                   )
            ');
            $query->execute([$user['id'], $user['id']]);
        } else {
            $query = $db->query('
                SELECT DISTINCT u.id, CONCAT(u.first_name, " ", u.last_name) AS name
                FROM users u JOIN services s ON s.owner_id = u.id
            ');
        }
        $accounts = $query->fetchAll(PDO::FETCH_ASSOC);
        foreach ($accounts as &$account) {
            $account['id'] = (int)$account['id'];
        }
        unset($account);

        $conversations = [];
        if ($user) {
            $query = $db->prepare('
                SELECT c.id, c.service_id AS serviceId, c.updated_at AS updatedAt
                FROM conversations c
                JOIN conversation_participants cp ON cp.conversation_id = c.id
                WHERE cp.user_id = ? ORDER BY c.updated_at DESC
            ');
            $query->execute([$user['id']]);
            foreach ($query->fetchAll(PDO::FETCH_ASSOC) as $conversation) {
                $participantsQuery = $db->prepare('SELECT user_id AS id FROM conversation_participants WHERE conversation_id = ?');
                $participantsQuery->execute([$conversation['id']]);
                $conversation['participants'] = array_map('intval', $participantsQuery->fetchAll(PDO::FETCH_COLUMN));
                $messagesQuery = $db->prepare('
                    SELECT m.sender_id AS sender, m.`text`, m.created_at AS createdAt
                    FROM messages m WHERE m.conversation_id = ? ORDER BY m.id
                ');
                $messagesQuery->execute([$conversation['id']]);
                $conversation['messages'] = $messagesQuery->fetchAll(PDO::FETCH_ASSOC);
                foreach ($conversation['messages'] as &$message) {
                    $message['sender'] = (int)$message['sender'];
                }
                unset($message);
                $conversations[] = $conversation;
            }
        }
        respond(200, ['user' => $user, 'services' => $services, 'accounts' => $accounts, 'conversations' => $conversations]);
    }

    if ($method === 'POST' && $path === 'auth/signup') {
        $firstName = trim(is_string($body['firstName'] ?? null) ? $body['firstName'] : '');
        $lastName = trim(is_string($body['lastName'] ?? null) ? $body['lastName'] : '');
        $email = strtolower(trim(is_string($body['email'] ?? null) ? $body['email'] : ''));
        $password = is_string($body['password'] ?? null) ? $body['password'] : '';
        $wilaya = trim(is_string($body['wilaya'] ?? null) ? $body['wilaya'] : '');
        if (stringLength($firstName) < 1 || stringLength($firstName) > 40
            || stringLength($lastName) < 1 || stringLength($lastName) > 40
            || !filter_var($email, FILTER_VALIDATE_EMAIL) || strlen($email) > 254
            || stringLength($wilaya) < 1 || stringLength($wilaya) > 60 || !validPassword($password)) {
            fail(400, 'تحقق من البيانات المدخلة، ويجب أن تحتوي كلمة المرور على حرف ورقم.');
        }
        $query = $db->prepare('SELECT id FROM users WHERE email = ?');
        $query->execute([$email]);
        if ($query->fetchColumn()) {
            fail(409, 'يوجد حساب بهذا البريد. سجّل الدخول بدلًا من ذلك.');
        }
        try {
            $db->prepare('
                INSERT INTO users (first_name, last_name, email, account_type, phone, wilaya, password_salt, password_hash, created_at)
                VALUES (?, ?, ?, "customer", "", ?, "", ?, ?)
            ')->execute([$firstName, $lastName, $email, $wilaya, newPasswordHash($password), nowIso()]);
        } catch (PDOException $error) {
            if ($error->getCode() === '23000') {
                fail(409, 'يوجد حساب بهذا البريد. سجّل الدخول بدلًا من ذلك.');
            }
            throw $error;
        }
        $userId = (int)$db->lastInsertId();
        createUserSession($db, $userId);
        $query = $db->prepare('
            SELECT id, first_name AS firstName, last_name AS lastName,
                   CONCAT(first_name, " ", last_name) AS name, email,
                   "all" AS accountType, phone, wilaya
            FROM users WHERE id = ?
        ');
        $query->execute([$userId]);
        $user = $query->fetch(PDO::FETCH_ASSOC);
        $user['id'] = (int)$user['id'];
        respond(201, ['user' => $user]);
    }

    if ($method === 'POST' && $path === 'auth/login') {
        $ip = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        if (loginIsLimited($db, 'user', $ip, (string)$config['app_secret'])) {
            fail(429, 'محاولات كثيرة. انتظر 15 دقيقة ثم حاول مجددًا.');
        }
        $email = strtolower(trim(is_string($body['email'] ?? null) ? $body['email'] : ''));
        $password = is_string($body['password'] ?? null) ? $body['password'] : '';
        $query = $db->prepare('SELECT * FROM users WHERE email = ? LIMIT 1');
        $query->execute([$email]);
        $account = $query->fetch(PDO::FETCH_ASSOC);
        if (!$account || !login($db, $account, $password)) {
            if ($account && strlen((string)$account['password_hash']) === 128 && ctype_xdigit((string)$account['password_hash'])) {
                fail(401, 'هذا حساب قديم نُقل من SQLite. استخدم رمز نقل الحساب لإعداد كلمة مرور جديدة.');
            }
            fail(401, 'البريد الإلكتروني أو كلمة المرور غير صحيحة.');
        }
        clearLoginLimit($db, 'user', $ip, (string)$config['app_secret']);
        createUserSession($db, (int)$account['id']);
        $userQuery = $db->prepare('
            SELECT id, first_name AS firstName, last_name AS lastName,
                   CONCAT(first_name, " ", last_name) AS name, email,
                   "all" AS accountType, phone, wilaya
            FROM users WHERE id = ?
        ');
        $userQuery->execute([(int)$account['id']]);
        $user = $userQuery->fetch(PDO::FETCH_ASSOC);
        $user['id'] = (int)$user['id'];
        respond(200, ['user' => $user]);
    }

    if ($method === 'POST' && $path === 'auth/migrate-password') {
        $email = strtolower(trim(is_string($body['email'] ?? null) ? $body['email'] : ''));
        $token = trim(is_string($body['token'] ?? null) ? $body['token'] : '');
        $password = is_string($body['password'] ?? null) ? $body['password'] : '';
        if (!filter_var($email, FILTER_VALIDATE_EMAIL) || $token === '' || strlen($token) > 128 || !validPassword($password)) {
            fail(400, 'أدخل البريد ورمز النقل وكلمة مرور جديدة صحيحة.');
        }
        $db->beginTransaction();
        try {
            $query = $db->prepare('
                SELECT t.user_id FROM migration_reset_tokens t
                JOIN users u ON u.id = t.user_id
                WHERE u.email = ? AND t.token_hash = ? AND t.expires_at > ?
                FOR UPDATE
            ');
            $query->execute([$email, hash('sha256', $token), (int)floor(microtime(true) * 1000)]);
            $userId = $query->fetchColumn();
            if (!$userId) {
                $db->rollBack();
                fail(400, 'رمز النقل غير صحيح أو منتهي الصلاحية.');
            }
            $db->prepare('UPDATE users SET password_salt = "", password_hash = ? WHERE id = ?')
                ->execute([newPasswordHash($password), (int)$userId]);
            $db->prepare('DELETE FROM migration_reset_tokens WHERE user_id = ?')->execute([(int)$userId]);
            $db->commit();
        } catch (Throwable $error) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $error;
        }
        createUserSession($db, (int)$userId);
        respond(200, ['user' => ['id' => (int)$userId]]);
    }

    if ($method === 'GET' && $path === 'auth/me') {
        respond(200, ['user' => requestUser($db)]);
    }

    if ($method === 'POST' && $path === 'auth/logout') {
        $token = requestCookies()['khdemli_session'] ?? '';
        if (is_string($token) && $token !== '') {
            $db->prepare('DELETE FROM sessions WHERE token_hash = ?')->execute([hash('sha256', $token)]);
        }
        clearAuthCookie('khdemli_session');
        respond(204);
    }

    if ($method === 'GET' && $path === 'admin/auth/me') {
        $adminPasswordLength = stringLength((string)($config['admin_password'] ?? ''));
        $enabled = is_string($config['admin_password'] ?? null)
            && $adminPasswordLength >= 16
            && $adminPasswordLength <= 128
            && !str_starts_with((string)$config['admin_password'], 'REPLACE_');
        respond(200, ['enabled' => $enabled, 'authenticated' => $enabled && adminSession($db) !== null]);
    }

    if ($method === 'POST' && $path === 'admin/auth/login') {
        $adminPassword = (string)($config['admin_password'] ?? '');
        $adminPasswordLength = stringLength($adminPassword);
        if ($adminPasswordLength < 16 || $adminPasswordLength > 128 || str_starts_with($adminPassword, 'REPLACE_')) {
            fail(503, 'دخول الإدارة غير مفعّل. ضع كلمة مرور سرية قوية بطول 16 حرفاً على الأقل في إعدادات api/config.php.');
        }
        $ip = (string)($_SERVER['REMOTE_ADDR'] ?? 'unknown');
        if (loginIsLimited($db, 'admin', $ip, (string)$config['app_secret'])) {
            fail(429, 'محاولات دخول كثيرة. انتظر 15 دقيقة ثم حاول مجدداً.');
        }
        $password = is_string($body['password'] ?? null) ? $body['password'] : '';
        if (strlen($password) > 128 || !hash_equals($adminPassword, $password)) {
            fail(401, 'كلمة مرور الإدارة غير صحيحة.');
        }
        clearLoginLimit($db, 'admin', $ip, (string)$config['app_secret']);
        $token = rtrim(strtr(base64_encode(random_bytes(32)), '+/', '-_'), '=');
        $hash = hash('sha256', $token);
        $db->prepare('INSERT INTO admin_sessions (token_hash, expires_at) VALUES (?, ?)')
            ->execute([$hash, (int)floor(microtime(true) * 1000) + 14 * 24 * 60 * 60 * 1000]);
        setAuthCookie('khdemli_admin', $token, 'Strict');
        recordAdminAction($db, 'login');
        respond(200, ['authenticated' => true]);
    }

    if ($method === 'POST' && $path === 'admin/auth/logout') {
        $session = requireAdmin($db);
        recordAdminAction($db, 'logout');
        $db->prepare('DELETE FROM admin_sessions WHERE token_hash = ?')->execute([$session]);
        clearAuthCookie('khdemli_admin', 'Strict');
        respond(204);
    }

    if ($method === 'GET' && $path === 'admin/services') {
        requireAdmin($db);
        recordAdminAction($db, 'list_services');
        $services = $db->query('
            SELECT s.id, s.title, s.category, s.area, s.price, s.created_at AS createdAt,
                   s.owner_id AS ownerId, CONCAT(u.first_name, " ", u.last_name) AS ownerName
            FROM services s JOIN users u ON u.id = s.owner_id ORDER BY s.created_at DESC
        ')->fetchAll(PDO::FETCH_ASSOC);
        foreach ($services as &$service) {
            $service['price'] = (int)$service['price'];
            $service['ownerId'] = (int)$service['ownerId'];
        }
        unset($service);
        respond(200, ['services' => $services]);
    }

    if ($method === 'DELETE' && preg_match('~^admin/services/([^/]+)$~', $path, $match)) {
        requireAdmin($db);
        $serviceId = rawurldecode($match[1]);
        $query = $db->prepare('SELECT id FROM services WHERE id = ?');
        $query->execute([$serviceId]);
        $id = $query->fetchColumn();
        if (!$id) {
            fail(404, 'الخدمة غير موجودة.');
        }
        $db->beginTransaction();
        try {
            recordAdminAction($db, 'delete_service', (string)$id);
            $db->prepare('DELETE FROM services WHERE id = ?')->execute([$id]);
            $db->commit();
        } catch (Throwable $error) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $error;
        }
        respond(204);
    }

    if ($method === 'GET' && $path === 'admin/conversations') {
        requireAdmin($db);
        recordAdminAction($db, 'list_conversations');
        $conversations = $db->query('
            SELECT c.id, c.updated_at AS updatedAt, s.id AS serviceId, s.title AS serviceTitle,
                   c.requester_id AS requesterId,
                   CONCAT(requester.first_name, " ", requester.last_name) AS requesterName,
                   s.owner_id AS providerId,
                   CONCAT(provider.first_name, " ", provider.last_name) AS providerName,
                   (SELECT COUNT(*) FROM messages m WHERE m.conversation_id = c.id) AS messageCount
            FROM conversations c
            JOIN services s ON s.id = c.service_id
            JOIN users requester ON requester.id = c.requester_id
            JOIN users provider ON provider.id = s.owner_id
            ORDER BY c.updated_at DESC
        ')->fetchAll(PDO::FETCH_ASSOC);
        foreach ($conversations as &$conversation) {
            foreach (['requesterId', 'providerId', 'messageCount'] as $field) {
                $conversation[$field] = (int)$conversation[$field];
            }
        }
        unset($conversation);
        respond(200, ['conversations' => $conversations]);
    }

    if ($method === 'GET' && preg_match('~^admin/conversations/([^/]+)$~', $path, $match)) {
        requireAdmin($db);
        $conversationId = rawurldecode($match[1]);
        $query = $db->prepare('
            SELECT c.id, c.updated_at AS updatedAt, s.title AS serviceTitle,
                   CONCAT(requester.first_name, " ", requester.last_name) AS requesterName,
                   CONCAT(provider.first_name, " ", provider.last_name) AS providerName
            FROM conversations c
            JOIN services s ON s.id = c.service_id
            JOIN users requester ON requester.id = c.requester_id
            JOIN users provider ON provider.id = s.owner_id
            WHERE c.id = ?
        ');
        $query->execute([$conversationId]);
        $conversation = $query->fetch(PDO::FETCH_ASSOC);
        if (!$conversation) {
            fail(404, 'المحادثة غير موجودة.');
        }
        recordAdminAction($db, 'view_conversation', $conversationId);
        $messagesQuery = $db->prepare('
            SELECT CONCAT(u.first_name, " ", u.last_name) AS senderName, m.`text`, m.created_at AS createdAt
            FROM messages m JOIN users u ON u.id = m.sender_id
            WHERE m.conversation_id = ? ORDER BY m.id
        ');
        $messagesQuery->execute([$conversationId]);
        respond(200, ['conversation' => $conversation, 'messages' => $messagesQuery->fetchAll(PDO::FETCH_ASSOC)]);
    }

    if ($method === 'GET' && preg_match('~^accounts/([0-9]+)/profile$~', $path, $match)) {
        $accountId = (int)$match[1];
        if ($accountId < 1) {
            fail(400, 'معرّف الحساب غير صالح.');
        }
        $query = $db->prepare('SELECT id, CONCAT(first_name, " ", last_name) AS name, wilaya FROM users WHERE id = ?');
        $query->execute([$accountId]);
        $account = $query->fetch(PDO::FETCH_ASSOC);
        if (!$account) {
            fail(404, 'لم نعثر على ملف مقدم الخدمة.');
        }
        $account['id'] = (int)$account['id'];
        $summaryQuery = $db->prepare('SELECT COUNT(*) AS count, AVG(rating) AS average FROM provider_reviews WHERE provider_id = ?');
        $summaryQuery->execute([$accountId]);
        $summary = $summaryQuery->fetch(PDO::FETCH_ASSOC);
        $reviewsQuery = $db->prepare('
            SELECT r.id, r.reviewer_id AS reviewerId,
                   CONCAT(u.first_name, " ", u.last_name) AS reviewerName,
                   r.rating, r.`comment`, r.created_at AS createdAt, r.updated_at AS updatedAt
            FROM provider_reviews r JOIN users u ON u.id = r.reviewer_id
            WHERE r.provider_id = ? ORDER BY r.created_at DESC
        ');
        $reviewsQuery->execute([$accountId]);
        $reviews = $reviewsQuery->fetchAll(PDO::FETCH_ASSOC);
        foreach ($reviews as &$review) {
            $review['id'] = (int)$review['id'];
            $review['reviewerId'] = (int)$review['reviewerId'];
            $review['rating'] = (int)$review['rating'];
        }
        unset($review);
        $user = requestUser($db);
        $ownReview = null;
        $canReview = false;
        if ($user) {
            $ownQuery = $db->prepare('
                SELECT id, rating, `comment`, created_at AS createdAt, updated_at AS updatedAt
                FROM provider_reviews WHERE provider_id = ? AND reviewer_id = ?
            ');
            $ownQuery->execute([$accountId, $user['id']]);
            $ownReview = $ownQuery->fetch(PDO::FETCH_ASSOC) ?: null;
            if ($ownReview) {
                $ownReview['id'] = (int)$ownReview['id'];
                $ownReview['rating'] = (int)$ownReview['rating'];
            }
            $canReview = $ownReview !== null || hasTwoWayConversation($db, $user['id'], $accountId);
        }
        respond(200, [
            'account' => $account,
            'rating' => [
                'average' => $summary['average'] === null ? null : (float)$summary['average'],
                'count' => (int)$summary['count'],
            ],
            'reviews' => $reviews,
            'canReview' => $canReview,
            'ownReview' => $ownReview,
        ]);
    }

    if ($method === 'POST' && preg_match('~^accounts/([0-9]+)/reviews$~', $path, $match)) {
        $user = requireUser($db);
        $providerId = (int)$match[1];
        $rating = filter_var($body['rating'] ?? null, FILTER_VALIDATE_INT);
        $comment = trim(is_string($body['comment'] ?? null) ? $body['comment'] : '');
        if ($providerId < 1 || $rating === false || $rating < 1 || $rating > 5) {
            fail(400, 'اختر تقييماً صحيحاً من نجمة إلى خمس نجوم.');
        }
        if (stringLength($comment) < 5 || stringLength($comment) > 1000) {
            fail(400, 'اكتب مراجعة من 5 إلى 1000 حرف.');
        }
        if ($providerId === $user['id']) {
            fail(400, 'لا يمكنك تقييم نفسك.');
        }
        $providerQuery = $db->prepare('SELECT id FROM users WHERE id = ?');
        $providerQuery->execute([$providerId]);
        if (!$providerQuery->fetchColumn()) {
            fail(404, 'لم نعثر على مقدم الخدمة.');
        }
        $existingQuery = $db->prepare('SELECT id FROM provider_reviews WHERE provider_id = ? AND reviewer_id = ?');
        $existingQuery->execute([$providerId, $user['id']]);
        $existing = $existingQuery->fetchColumn();
        if (!$existing && !hasTwoWayConversation($db, $user['id'], $providerId)) {
            fail(403, 'يتاح تقييم مقدم الخدمة بعد تبادل الرسائل معه عبر المنصة.');
        }
        $now = nowIso();
        $db->prepare('
            INSERT INTO provider_reviews (provider_id, reviewer_id, rating, `comment`, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
            ON DUPLICATE KEY UPDATE rating = VALUES(rating), `comment` = VALUES(`comment`), updated_at = VALUES(updated_at)
        ')->execute([$providerId, $user['id'], $rating, $comment, $now, $now]);
        $savedQuery = $db->prepare('
            SELECT id, rating, `comment`, created_at AS createdAt, updated_at AS updatedAt
            FROM provider_reviews WHERE provider_id = ? AND reviewer_id = ?
        ');
        $savedQuery->execute([$providerId, $user['id']]);
        $saved = $savedQuery->fetch(PDO::FETCH_ASSOC);
        $saved['id'] = (int)$saved['id'];
        $saved['rating'] = (int)$saved['rating'];
        respond($existing ? 200 : 201, $saved);
    }

    if ($method === 'POST' && $path === 'services') {
        $user = requireUser($db);
        $title = trim(is_string($body['title'] ?? null) ? $body['title'] : '');
        $description = trim(is_string($body['description'] ?? null) ? $body['description'] : '');
        $category = is_string($body['category'] ?? null) ? $body['category'] : '';
        $area = trim(is_string($body['area'] ?? null) ? $body['area'] : '');
        $price = filter_var($body['price'] ?? null, FILTER_VALIDATE_INT);
        if (stringLength($title) < 1 || stringLength($title) > 100
            || stringLength($description) < 20 || stringLength($description) > 3000
            || !in_array($category, ['design', 'programming', 'writing', 'marketing', 'video', 'business'], true)
            || stringLength($area) < 1 || stringLength($area) > 60
            || $price === false || $price < 1 || $price > 100000000) {
            fail(400, 'تحقق من عنوان الخدمة وتصنيفها وولايتها وسعرها ووصفها.');
        }
        $service = [
            'id' => uuidV4(),
            'owner' => $user['id'],
            'title' => $title,
            'category' => $category,
            'area' => $area,
            'price' => $price,
            'description' => $description,
            'createdAt' => nowIso(),
        ];
        $db->prepare('
            INSERT INTO services (id, owner_id, title, category, area, price, description, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ')->execute([$service['id'], $service['owner'], $title, $category, $area, $price, $description, $service['createdAt']]);
        respond(201, ['service' => $service]);
    }

    if ($method === 'DELETE' && preg_match('~^services/([^/]+)$~', $path, $match)) {
        $user = requireUser($db);
        $serviceId = rawurldecode($match[1]);
        $delete = $db->prepare('DELETE FROM services WHERE id = ? AND owner_id = ?');
        $delete->execute([$serviceId, $user['id']]);
        if ($delete->rowCount() < 1) {
            fail(404, 'الخدمة غير موجودة أو لا تملك صلاحية حذفها.');
        }
        respond(204);
    }

    if ($method === 'POST' && $path === 'conversations') {
        $user = requireUser($db);
        $serviceId = is_string($body['serviceId'] ?? null) ? $body['serviceId'] : '';
        if ($serviceId === '') {
            fail(400, 'حدد خدمة لبدء المحادثة.');
        }
        $serviceQuery = $db->prepare('SELECT id, owner_id AS owner FROM services WHERE id = ?');
        $serviceQuery->execute([$serviceId]);
        $service = $serviceQuery->fetch(PDO::FETCH_ASSOC);
        if (!$service) {
            fail(404, 'لم نعثر على هذه الخدمة.');
        }
        if ((int)$service['owner'] === $user['id']) {
            fail(400, 'لا يمكنك مراسلة نفسك.');
        }
        $existingQuery = $db->prepare('SELECT id FROM conversations WHERE service_id = ? AND requester_id = ?');
        $existingQuery->execute([$serviceId, $user['id']]);
        $conversationId = $existingQuery->fetchColumn();
        if ($conversationId) {
            respond(200, ['conversation' => ['id' => $conversationId]]);
        }
        $conversationId = uuidV4();
        $createdAt = nowIso();
        $db->beginTransaction();
        try {
            $db->prepare('INSERT INTO conversations (id, service_id, requester_id, updated_at) VALUES (?, ?, ?, ?)')
                ->execute([$conversationId, $serviceId, $user['id'], $createdAt]);
            $db->prepare('INSERT INTO conversation_participants (conversation_id, user_id) VALUES (?, ?), (?, ?)')
                ->execute([$conversationId, (int)$service['owner'], $conversationId, $user['id']]);
            $db->commit();
        } catch (PDOException $error) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            if ($error->getCode() === '23000') {
                $existingQuery->execute([$serviceId, $user['id']]);
                $existing = $existingQuery->fetchColumn();
                if ($existing) {
                    respond(200, ['conversation' => ['id' => $existing]]);
                }
            }
            throw $error;
        }
        respond(201, ['conversation' => ['id' => $conversationId, 'serviceId' => $serviceId, 'updatedAt' => $createdAt]]);
    }

    if ($method === 'POST' && $path === 'messages') {
        $user = requireUser($db);
        $conversationId = is_string($body['conversationId'] ?? null) ? $body['conversationId'] : '';
        $text = trim(is_string($body['text'] ?? null) ? $body['text'] : '');
        $conversationQuery = $db->prepare('
            SELECT c.id FROM conversations c
            JOIN conversation_participants cp ON cp.conversation_id = c.id
            WHERE c.id = ? AND cp.user_id = ?
        ');
        $conversationQuery->execute([$conversationId, $user['id']]);
        if (!$conversationQuery->fetchColumn()) {
            fail(404, 'لا يمكن العثور على محادثة تخص حسابك.');
        }
        if ($text === '' || stringLength($text) > 1000) {
            fail(400, 'يجب أن تكون الرسالة بين حرف واحد و1000 حرف.');
        }
        $createdAt = nowIso();
        $db->beginTransaction();
        try {
            $db->prepare('INSERT INTO messages (conversation_id, sender_id, `text`, created_at) VALUES (?, ?, ?, ?)')
                ->execute([$conversationId, $user['id'], $text, $createdAt]);
            $db->prepare('UPDATE conversations SET updated_at = ? WHERE id = ?')->execute([$createdAt, $conversationId]);
            $db->commit();
        } catch (Throwable $error) {
            if ($db->inTransaction()) {
                $db->rollBack();
            }
            throw $error;
        }
        respond(201, ['message' => ['sender' => $user['id'], 'text' => $text, 'createdAt' => $createdAt]]);
    }

    fail(404, 'واجهة API غير موجودة.');
}

if (!is_file(__DIR__ . '/config.php')) {
    fail(503, 'أكمل إعداد api/config.php واتصال MySQL قبل تشغيل واجهة الموقع.');
}

try {
    $config = require __DIR__ . '/config.php';
    if (!is_array($config)) {
        throw new RuntimeException('Invalid api/config.php');
    }
    foreach (['db_host', 'db_name', 'db_user', 'db_password', 'admin_password'] as $key) {
        if (!isset($config[$key]) || !is_string($config[$key])) {
            throw new RuntimeException('Missing configuration value: ' . $key);
        }
    }
    $config['app_secret'] = (string)($config['app_secret'] ?? '');
    if (strlen($config['app_secret']) < 32 || str_starts_with($config['app_secret'], 'REPLACE_')) {
        throw new RuntimeException('Set app_secret to a random secret of at least 32 characters in api/config.php');
    }
    $db = new PDO(
        'mysql:host=' . $config['db_host'] . ';dbname=' . $config['db_name'] . ';charset=utf8mb4',
        $config['db_user'],
        $config['db_password'],
        [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_EMULATE_PREPARES => false,
        ]
    );
    run($db, $config);
} catch (Throwable $error) {
    error_log('KHDEMLI API error: ' . $error->getMessage());
    fail(500, 'تعذّر تنفيذ الطلب على الخادم. راجع إعداد قاعدة البيانات وسجل أخطاء PHP.');
}
