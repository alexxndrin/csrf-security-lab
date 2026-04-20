<?php
// запуск сессии для хранения токена
if (session_status() !== PHP_SESSION_ACTIVE) {
    session_start();
}

class CsrfGuard
{
    /**
     * генерирует криптографически стойкий токен и сохраняет его в сессии
     * 
     * что делает метод:
     * - создаёт случайную строку из 64 символов (hex)
     * - сохраняет её в $_SESSION['csrf_token']
     * - возвращает сгенерированный токен
     * 
     * почему именно так:
     * - random_bytes(32) генерирует 32 случайных байта, что даёт 256 бит энтропии,
     *   это делает подбор токена практически невозможным
     * - bin2hex преобразует бинарные данные в строку из hex-символов (0-9, a-f),
     *   такую строку безопасно хранить в сессии и передавать в html
     * - токен хранится в сессии, потому что сессия привязана к конкретному
     *   пользователю через cookie PHPSESSID и автоматически очищается при закрытии
     *   браузера или истечении времени жизни сессии, в отличие от базы данных,
     *   где пришлось бы вручную удалять устаревшие токены
     */
    public static function generate()
    {
        $token = bin2hex(random_bytes(32));
        $_SESSION['csrf_token'] = $token;
        return $token;
    }
    
    /**
     * возвращает html-код скрытого поля с csrf-токеном для вставки в форму
     * 
     * что делает метод:
     * - вызывает generate() для создания нового токена
     * - формирует строку с тегом <input type="hidden">
     * - возвращает готовый html-код
     * 
     * почему именно так:
     * - вызов generate() внутри метода гарантирует, что при каждой загрузке
     *   страницы с формой будет создан новый токен
     * - скрытое поле (type="hidden") не отображается пользователю, но его
     *   значение автоматически отправляется браузером вместе с остальными
     *   полями формы при нажатии на кнопку отправки
     * - имя поля _csrf_token выбрано так, чтобы не конфликтовать с другими
     *   полями формы и быть понятным при отладке
     */
    public static function embed()
    {
        $token = self::generate();
        return '<input type="hidden" name="_csrf_token" value="' . $token . '">';
    }

    /**
     * проверяет, совпадает ли токен из запроса с токеном в сессии
     * 
     * что делает метод:
     * - проверяет наличие токена в сессии
     * - проверяет, что переданный токен не пустой
     * - сравнивает токен из запроса с токеном из сессии
     * - возвращает true при совпадении, иначе false
     * 
     * почему именно так:
     * - сначала проверяется isset($_SESSION['csrf_token']), потому что если
     *   токена в сессии нет, значит пользователь либо не загружал форму,
     *   либо его сессия истекла, в любом случае запрос нужно отклонить
     * - проверка empty($inputToken) отсеивает запросы, в которых поле
     *   _csrf_token отсутствует или содержит пустую строку
     * - для сравнения используется hash_equals() вместо оператора ===,
     *   потому что hash_equals() выполняет сравнение за постоянное время
     *   независимо от того, на каком символе найдено различие, это
     *   предотвращает атаки по времени (timing attacks), когда злоумышленник
     *   может подобрать токен, замеряя время ответа сервера
     */
    public static function validate($inputToken)
    {
        if (!isset($_SESSION['csrf_token'])) {
            return false;
        }
        if (empty($inputToken)) {
            return false;
        }
        return hash_equals($_SESSION['csrf_token'], $inputToken);
    }
}

// переменные для сообщений
$message = '';
$messageType = '';

// обработка формы создания объявления
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'create') {
    $inputToken = $_POST['_csrf_token'] ?? '';
    if (!CsrfGuard::validate($inputToken)) {
        $message = 'Ошибка безопасности: недействительный CSRF-токен. Запрос отклонён.';
        $messageType = 'error';
    } else {
        $title = htmlspecialchars($_POST['title'] ?? '');
        $price = (int)($_POST['price'] ?? 0);
        $message = 'Объявление "' . $title . '" за ' . $price . ' руб. успешно создано.';
        $messageType = 'success';
    }
}

// обработка формы обновления профиля
if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['action']) && $_POST['action'] === 'profile') {
    $inputToken = $_POST['_csrf_token'] ?? '';
    if (!CsrfGuard::validate($inputToken)) {
        $message = 'Ошибка безопасности: недействительный CSRF-токен. Профиль не обновлён.';
        $messageType = 'error';
    } else {
        $email = htmlspecialchars($_POST['email'] ?? '');
        $message = 'Профиль обновлён. Новый email: ' . $email;
        $messageType = 'success';
    }
}
?>
<!DOCTYPE html>
<html lang="ru">
<head>
    <meta charset="UTF-8">
    <title>CSRF защита</title>
    <style>
        body { font-family: Arial, sans-serif; max-width: 500px; margin: 30px auto; padding: 0 15px; }
        .box { border: 1px solid #ccc; padding: 20px; margin-bottom: 20px; border-radius: 4px; }
        input { width: 100%; padding: 8px; margin: 5px 0 12px; box-sizing: border-box; }
        button { background: #007bff; color: #fff; border: none; padding: 10px 16px; cursor: pointer; width: 100%; }
        .success { background: #d4edda; color: #155724; padding: 12px; border-radius: 4px; margin-bottom: 15px; }
        .error { background: #f8d7da; color: #721c24; padding: 12px; border-radius: 4px; margin-bottom: 15px; }
        code { background: #eee; padding: 2px 4px; border-radius: 3px; }
    </style>
</head>
<body>

<h2>Доска объявлений (CSRF защита)</h2>

<?php if ($message): ?>
    <div class="<?= $messageType ?>"><?= $message ?></div>
<?php endif; ?>

<!-- форма 1: создание объявления -->
<div class="box">
    <h3>Создать объявление</h3>
    <form method="POST">
        <?= CsrfGuard::embed() ?>
        <input type="hidden" name="action" value="create">
        <label>Название:</label>
        <input type="text" name="title" placeholder="Продам гараж" required>
        <label>Цена (руб):</label>
        <input type="number" name="price" value="1000" required>
        <button type="submit">Создать</button>
    </form>
</div>

<!-- форма 2: обновление профиля -->
<div class="box">
    <h3>Обновить профиль</h3>
    <form method="POST">
        <?= CsrfGuard::embed() ?>
        <input type="hidden" name="action" value="profile">
        <label>Новый Email:</label>
        <input type="email" name="email" placeholder="user@example.com" required>
        <button type="submit">Обновить</button>
    </form>
</div>

</body>
</html>