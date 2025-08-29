
<img width="883" height="372" alt="Untitled" src="https://github.com/user-attachments/assets/a7a669ce-29f3-48cc-b316-d58550b5edbb" />

## JS Sensitive Scanner - это инструмент для анализа JavaScript-кода на наличие чувствительных данных, таких как API-ключи, токены, пароли, приватные ключи и другие конфиденциальные данные, оставшиеся в исходном коде. Он ищет такие данные в файлах JavaScript, TypeScript, JSON, а также в строках соединений и cookies

### **Поиск чувствительных данных:**
```
AWS Access Key ID, Secret Access Key
Google API Key, Firebase Config Key
GitHub Token, Slack Token
JWT-токены
Stripe Key, Private Keys (PEM)
Логины и пароли в коде
Строки подключения к базам данных (MongoDB, MySQL, PostgreSQL и другие)
Использование cookies и localStorage
```

### Поиск высокоэнтропийных строк - потенциальных токенов и ключей, которые могут быть сгенерированы или случайны.
### Обнаружение небезопасных операций:
### Использование eval, Function, localStorage, document.cookie, что может указывать на уязвимости в безопасности (например, XSS-атаки).

# Описание параметров:
```
--stdin: Позволяет передать код через стандартный ввод (например, с помощью echo).

--json <путь>: Сохраняет результаты сканирования в файл в формате JSON.

--top <N>: Параметр для ограничения вывода. Покажет только первые N результатов.

--include-node-modules: Включает папку node_modules в сканирование. Используйте этот параметр, если хотите анализировать зависимости.

--min-entropy <значение>: Устанавливает порог энтропии для поиска строк с высокой энтропией (например, для токенов и ключей)
```

# Пример:
```
Анализ одного файла
python3 js_sensitive_scan_v0.3.py <путь_к_файлу>

Рекурсивный анализ папки
python3 js_sensitive_scan_v0.3.py <путь_к_папке>

Использование stdin (анализ кода, переданного через консоль)
echo "const apiKey = 'AIza...';" | python3 js_sensitive_scan_v0.3.py --stdin

Сохранение результатов в JSON
python3 js_sensitive_scan_v0.3.py <путь_к_файлу> --json result.json

Показать только первые N результатов
python3 js_sensitive_scan_v0.3.py <путь_к_файлу> --top <N>

Включить сканирование node_modules (не рекомендуется)
python3 js_sensitive_scan_v0.3.py <путь_к_папке> --include-node-modules

Настройка порога энтропии для кандидатов с высокоэнтропийными строками
python3 js_sensitive_scan_v0.3.py <путь_к_файлу> --min-entropy <значение>
```
