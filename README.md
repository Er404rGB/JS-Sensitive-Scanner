JS Sensitive Scanner — это инструмент для анализа JavaScript-кода на наличие чувствительных данных, таких как API-ключи, токены, пароли, приватные ключи и другие конфиденциальные данные, оставшиеся в исходном коде. Он ищет такие данные в файлах JavaScript, TypeScript, JSON, а также в строках соединений и cookies.

Возможности

Поиск чувствительных данных:

AWS Access Key ID, Secret Access Key

Google API Key, Firebase Config Key

GitHub Token, Slack Token

JWT-токены

Stripe Key, Private Keys (PEM)

Логины и пароли в коде

Строки подключения к базам данных (MongoDB, MySQL, PostgreSQL и другие)

Использование cookies и localStorage

Поиск высокоэнтропийных строк — потенциальных токенов и ключей, которые могут быть сгенерированы или случайны.

Обнаружение небезопасных операций:

Использование eval, Function, localStorage, document.cookie, что может указывать на уязвимости в безопасности (например, XSS-атаки).
