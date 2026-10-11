# Лабораторна робота №2 — Розробка консольних утиліт для задач кібербезпеки

**Студентка:** Катерина Меснянкіна  
**Група:** КБ-203  
**Спеціальність:** Кібербезпека  
**Варіант:** 1 — Аналізатор журналів веб-сервера (Nginx/Apache Access Log)

## Опис

| Команда   | Завдання   | Що робить                                                                    |
|-----------|------------|------------------------------------------------------------------------------|
| `demo`    | Завдання 1 | Демонстрація ООП-моделі: `User`, `Admin`, `Session`, `AuditLog`, `UserAccount` |
| `analyze` | Завдання 2 | Аналіз `access.log`: топ IP з помилками, сигнатури атак, фільтр за часом, звіт JSON/CSV |

## Встановлення залежностей

Усі команди виконуються **з кореня репозиторію**, модулі запускаються через `python -m ...`.

```bash
python -m venv .venv
# Windows:      .venv\Scripts\activate
# Linux/macOS:  source .venv/bin/activate
pip install -r requirements.txt
```

Потрібен Python 3.10+. Утиліта використовує лише стандартну бібліотеку; єдина залежність
проєкту — `ruff` (перевірка стилю).

## Структура файлів

```
cybersecurity-python-labs/
├── .gitignore
├── requirements.txt
├── shared/
│   ├── __init__.py
│   └── student.py            # STUDENT_NAME, GROUP_NAME, VARIANT_NUMBER = 1
└── labs/
    ├── __init__.py
    ├── lab01/                # ЛР №1
    └── lab02/
        ├── __init__.py
        ├── main.py           # команди demo та analyze
        ├── task1.py          # класи та демонстрація ООП
        ├── task2.py          # аналізатор access.log (варіант 1)
        ├── README.md
        └── data/
            └── data_v01/
                └── access.log
```

## Вхідні дані

Програма приймає на вхід один файл — `labs/lab02/data/data_v01/access.log`
(текстовий журнал у форматі Common/Combined Log Format; необов'язкові поля Referer та
User-Agent у кінці рядка підтримуються):

```
203.0.113.99 - - [27/Sep/2026:18:30:00 +0300] "GET /login?user=admin' OR '1'='1 HTTP/1.1" 401 800
│              │ │ │                           │    │                              │         │   │
IP             │ │ дата/час (з поясом)         метод URI                            протокол  код розмір
```

Рядки, що не відповідають формату, пропускаються з попередженням у лозі (див. нижче).

## Запуск

### Завдання 1 — демонстрація

```bash
python -m labs.lab02.main demo
```

### Завдання 2 — аналіз журналу

```bash
# Базовий запуск (файл за замовчуванням — data/data_v01/access.log, звіт JSON поруч із ним)
python -m labs.lab02.main analyze

# Явні параметри, топ-3 IP, звіт у JSON
python -m labs.lab02.main analyze \
    --log-file labs/lab02/data/data_v01/access.log \
    --output labs/lab02/data/data_v01/web_analysis_report.json \
    --min-status 400 --top 3 --format json

# Звіт у CSV
python -m labs.lab02.main analyze \
    --log-file labs/lab02/data/data_v01/access.log \
    --output labs/lab02/data/data_v01/web_analysis_report.csv --format csv

# Фільтрація за часовим інтервалом (лише вечірні запити)
python -m labs.lab02.main analyze \
    --log-file labs/lab02/data/data_v01/access.log \
    --since "2026-09-27 18:00:00" --until "2026-09-27 19:00:00"

# Лише відповіді 5xx, детальний лог
python -m labs.lab02.main analyze --min-status 500 --verbose
```

(У PowerShell символ продовження рядка — `` ` `` замість `\`; або запишіть команду в один рядок.)

### Приклад виводу

```text
[INFO] Loading access log from labs/lab02/data/data_v01/access.log...
[INFO] Processed 68 log entries from 2026-09-27 08:00:00 to 2026-09-27 19:06:00.

=== Top-3 IP Addresses with Error Statuses (4xx/5xx) ===
203.0.113.99 - 18 errors (404: 9, 400: 4, 401: 2, 403: 2, 500: 1)
192.0.2.11 - 7 errors (401: 3, 400: 2, 404: 1, 500: 1)
192.0.2.10 - 4 errors (500: 2, 400: 1, 403: 1)

=== Detected Attack Signatures ===
[ALERT] Potential SQLi from 203.0.113.99: "GET /login?user=admin' OR '1'='1"
[ALERT] Potential SQLi from 203.0.113.99: "GET /search?q=1%27%20OR%201%3D1--"
[ALERT] Potential Directory Traversal from 203.0.113.99: "GET /../../etc/passwd"
[ALERT] Potential Directory Traversal from 203.0.113.99: "GET /download?file=../../../etc/shadow"
[ALERT] Potential XSS from 203.0.113.99: "GET /search?q=<script>alert(1)</script>"
[ALERT] Potential XSS from 203.0.113.99: "GET /comment?text=%3Cscript%3Ealert(1)%3C/script%3E"
Total alerts: 6 (SQLi: 2, Directory Traversal: 2, XSS: 2)
[INFO] Analysis report saved to labs/lab02/data/data_v01/web_analysis_report.json
```

Повідомлення `logging` (`[INFO]`, `[WARNING]`, `[ERROR]`) виводяться в `stderr`,
таблиці та `[ALERT]` — у `stdout`.

## Параметри командного рядка (`analyze`)

| Параметр        | Тип / значення      | За замовчуванням                               | Опис |
|-----------------|---------------------|------------------------------------------------|------|
| `--log-file`    | шлях                | `labs/lab02/data/data_v01/access.log`          | Журнал для аналізу |
| `--output`      | шлях                | `web_analysis_report.<format>` поруч із журналом | Файл звіту; відсутні каталоги створюються |
| `--min-status`  | ціле, 100–599       | `400`                                          | Мінімальний код відповіді, що вважається помилкою |
| `--top`         | ціле ≥ 1            | `5`                                            | Скільки IP показати в топі |
| `--format`      | `json` / `csv`      | за розширенням `--output` (`.csv` → csv), інакше json | Формат звіту |
| `--since`       | `YYYY-MM-DD[ HH:MM[:SS]]` | —                                        | Лише запити **не раніше** цього часу (включно) |
| `--until`       | `YYYY-MM-DD[ HH:MM[:SS]]` | —                                        | Лише запити **не пізніше** цього часу (включно) |
| `--verbose`     | прапорець           | вимкнено                                       | Рівень `DEBUG`: показує кожен пропущений рядок |

`--since`/`--until` без часового поясу порівнюються з «настінним» часом, записаним у журналі
(`18:30:00 +0300` → `18:30:00`). Щоб порівнювати з урахуванням пояса, вкажіть його явно:
`--since 2026-09-27T15:00:00+00:00`.

Перевірка типів виконується на рівні `argparse`: некоректне значення (`--min-status 99`,
`--top 0`, `--since abc`) зупиняє програму ще до читання файлу з кодом завершення `2`.

## Формат звіту

**JSON** — структура `source_file`, `parameters`, `summary` (кількість рядків, пропущених
рядків, оброблених записів, відповідей-помилок, перша/остання мітка часу), `top_error_ips`,
`attack_counts`, `attacks` (тип, IP, час, код відповіді, запит).

**CSV** — один файл зі стовпцем `section`: рядки `top_error_ip` (rank, ip, errors,
status_breakdown) та рядки `attack` (ip, timestamp, attack_type, status, request).
Значення, що починаються з `=`, `+`, `-`, `@`, екрануються апострофом (захист від CSV/formula
injection під час відкриття в Excel).

## Як виявляються атаки

Сигнатури — регулярні вирази `re`, які застосовуються до URI і до його декодованої форми
(`%XX`, `+`; до трьох раундів, проти подвійного кодування `%252e`).

| Тип                 | Що шукається                                                              |
|---------------------|---------------------------------------------------------------------------|
| SQLi                | `UNION SELECT`, `' OR '1'='1`, `OR 1=1`, лапка + коментар `--`/`#`, `SELECT … FROM`, `DROP TABLE`, `sleep()` |
| Directory Traversal | `../`, `..\`, `/etc/passwd`, `/etc/shadow`, `win.ini`                      |
| XSS                 | `<script`, `javascript:`, обробники подій (`onerror=`, `onload=` …), `<iframe>`/`<svg>` |

Це спрощений сигнатурний аналіз: він не замінює WAF, а в журналі доступу не видно тіла
POST-запитів.

## Поведінка при помилках

| Ситуація                                  | Реакція                                              | Код |
|-------------------------------------------|------------------------------------------------------|-----|
| Некоректний аргумент CLI                  | Повідомлення `argparse`                              | 2   |
| Файл журналу не знайдено / це каталог     | `[ERROR] Log file not found: …`                      | 1   |
| `--since` пізніше за `--until`            | `[ERROR] --since must not be later than --until`     | 1   |
| Помилка читання журналу (права доступу)   | `[ERROR] Cannot read …`                              | 1   |
| Не вдалося записати звіт                  | `[ERROR] Cannot write report to …`                   | 1   |
| Рядок не відповідає формату               | Рядок пропускається, підсумкове `[WARNING]` (деталі — з `--verbose`) | 0 |
| Порожній журнал / фільтр відсіяв усе      | `[WARNING] No log entries to analyze…`, звіт із нулями | 0   |
| Ctrl+C                                    | `[WARNING] Interrupted by user`                      | 130 |
| Успішне виконання                         | —                                                    | 0   |

Журнал читається порядково через генератор, тому великі файли не завантажуються в пам'ять
повністю. Керівні символи в запитах замінюються на `?` перед виводом і записом у звіт
(захист від log injection).

## Знайдені аномалії у `data_v01/access.log`

* Основний трафік (55 записів, 08:00–14:18, крок 7 хвилин) — звичайні запити від п'яти IP.
* **`203.0.113.99`** — лідер за помилками (18 з 35 відповідей-помилок). Після 18:30 з цієї
  адреси надходять:
  * 18:30–18:40 — шість запитів зі сигнатурами атак: 2× SQLi, 2× Directory Traversal,
    2× XSS (по одному запиту кожні 2 хвилини; коди 400/401/403/404/500);
  * 19:00–19:06 — послідовний перебір `/admin/0` … `/admin/6` (7 відповідей `404`,
    по одному запиту на хвилину) — схоже на розвідку прихованих адмін-ресурсів
    (forced browsing). Сигнатурами SQLi/Traversal/XSS цей патерн не охоплюється, але його
    видно за кількістю `404` у топі помилок.
* Усі шість атак отримали відповіді 4xx/5xx, тобто сервер їх відхилив; успішних (2xx)
  атакуючих запитів у журналі немає.

Рекомендація: заблокувати `203.0.113.99` на рівні фаєрвола/WAF і переглянути, чи не відкриті
з інтернету адмін-маршрути.

## Перевірка коду (Ruff)

```bash
ruff check .
ruff format --check .
# за потреби:
ruff check --fix .
ruff format .
```

Результати обох команд додаються до звіту.
