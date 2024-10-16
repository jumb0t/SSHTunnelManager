# SSH Tunnel Manager с веб-интерфейсом

Этот проект представляет собой скрипт на Python, который управляет множеством SSH-туннелей на основе конфигурационного файла JSON или файла, содержащего SSH-команды. Он включает в себя веб-интерфейс на базе Flask для мониторинга и управления туннелями в реальном времени.

## Оглавление

- [Особенности](#особенности)
- [Требования](#требования)
- [Установка](#установка)
- [Использование](#использование)
  - [Запуск скрипта](#запуск-скрипта)
  - [Аргументы командной строки](#аргументы-командной-строки)
- [Конфигурация](#конфигурация)
  - [Конфигурационный файл JSON](#конфигурационный-файл-json)
  - [Файл с SSH-командами](#файл-с-ssh-командами)
- [Веб-интерфейс](#веб-интерфейс)
  - [Главная страница](#главная-страница)
  - [Управление туннелями](#управление-туннелями)
  - [Добавление и редактирование туннелей](#добавление-и-редактирование-туннелей)
  - [Просмотр логов](#просмотр-логов)
- [Безопасность](#безопасность)
- [Зависимости](#зависимости)
- [Лицензия](#лицензия)
- [Автор](#автор)

## Особенности

- **Веб-интерфейс** доступен по адресу `http://127.0.0.1:9966` (по умолчанию)
- **Управление туннелями**: запуск, остановка, перезапуск через веб-интерфейс
- **Авто-переподключение**: настройка количества попыток переподключения для каждого туннеля
- **Индикация статуса**: цветовая подсветка строк туннелей в зависимости от их статуса
- **Переключение темы**: дневной/ночной режим
- **Локальные зависимости**: все CSS и JS файлы сервируются локально, без внешних зависимостей
- **Статистика**: отображение количества загруженных туннелей и их статусов
- **Сортировка**: возможность сортировки списка туннелей
- **Поддержка групп и комментариев** в конфигурационном файле
- **Безопасность**: возможность использования SSH-ключей для аутентификации

## Требования

- Python 3.6 или выше
- Установленные утилиты `ssh` и `sshpass`
- Библиотеки Python:
  - `flask`
  - `asyncio`

## Установка

1. **Клонируйте репозиторий или скачайте скрипт:**

   ```bash
   git clone https://github.com/yourusername/ssh-tunnel-manager.git
   cd ssh-tunnel-manager
   ```

2. **Установите необходимые зависимости:**

   ```bash
   pip install -r requirements.txt
   ```

   Или установите необходимые библиотеки вручную:

   ```bash
   pip install flask
   ```

3. **Убедитесь, что у вас установлены `ssh` и `sshpass`:**

   Для Ubuntu/Debian:

   ```bash
   sudo apt-get install ssh sshpass
   ```

   Для CentOS/RHEL:

   ```bash
   sudo yum install openssh sshpass
   ```

## Использование

### Запуск скрипта

```bash
python3 ssh_tunnel_manager.py -c config.json
```

Или, если вы используете файл с SSH-командами:

```bash
python3 ssh_tunnel_manager.py -c ssh_commands.txt
```

### Аргументы командной строки

- `-c`, `--config`: **(обязательно)** Путь к конфигурационному файлу JSON или файлу с SSH-командами.
- `--log-level`: Уровень логирования (`DEBUG`, `INFO`, `WARNING`, `ERROR`). По умолчанию `INFO`.
- `--web-host`: Хост для веб-интерфейса. По умолчанию `127.0.0.1`.
- `--web-port`: Порт для веб-интерфейса. По умолчанию `9966`.

**Пример:**

```bash
python3 ssh_tunnel_manager.py -c config.json --web-host 0.0.0.0 --web-port 8080 --log-level DEBUG
```

## Конфигурация

### Конфигурационный файл JSON

Файл конфигурации представляет собой список объектов JSON, каждый из которых описывает отдельный SSH-туннель.

**Пример `config.json`:**

```json
[
    {
        "name": "tunnel1",
        "host": "example.com",
        "port": 22,
        "username": "user",
        "password": "password",
        "local_port": 8080,
        "group": "Production",
        "comment": "Основной сервер",
        "serial_number": 1,
        "max_reconnects": 5
    },
    {
        "name": "tunnel2",
        "host": "test.com",
        "port": 2222,
        "username": "testuser",
        "password": "testpass",
        "local_port": 9090,
        "group": "Testing",
        "comment": "Тестовый сервер",
        "serial_number": 2,
        "max_reconnects": 3
    }
]
```

**Поля конфигурации:**

- `name` (строка): Имя туннеля (уникальное).
- `host` (строка): Адрес SSH-сервера.
- `port` (целое число): Порт SSH-сервера (обычно 22).
- `username` (строка): Имя пользователя для SSH.
- `password` (строка): Пароль пользователя (если используется аутентификация по паролю).
- `local_port` (целое число): Локальный порт для туннеля.
- `group` (строка, опционально): Группа, к которой относится туннель.
- `comment` (строка, опционально): Комментарий к туннелю.
- `serial_number` (целое число, опционально): Порядковый номер для сортировки.
- `max_reconnects` (целое число, опционально): Максимальное количество попыток переподключения.

### Файл с SSH-командами

Вы можете использовать файл, содержащий SSH-команды, каждая из которых будет преобразована в конфигурацию туннеля.

**Пример `ssh_commands.txt`:**

```bash
sshpass -p 'password' ssh -D 8080 -p 22 user@example.com
sshpass -p 'testpass' ssh -D 9090 -p 2222 testuser@test.com
```

**Примечания:**

- Команды должны быть полными и корректными.
- Поддерживаются опции `-p` для указания порта и `-D` для указания локального порта.
- Имя туннеля будет автоматически сгенерировано на основе хоста и локального порта.

## Веб-интерфейс

После запуска скрипта веб-интерфейс будет доступен по адресу `http://<web-host>:<web-port>`, который по умолчанию равен `http://127.0.0.1:9966`.

### Главная страница

На главной странице отображается список всех туннелей с информацией:

- **Имя**
- **Хост**
- **Порт**
- **Имя пользователя**
- **Локальный порт**
- **Статус** (запущен, остановлен, перезапускается)
- **Группа**
- **Комментарий**

Также отображается статистика по количеству туннелей и их статусам.

### Управление туннелями

- **Запуск**: Нажмите кнопку "Старт" рядом с туннелем.
- **Остановка**: Нажмите кнопку "Стоп" рядом с туннелем.
- **Перезапуск**: Нажмите кнопку "Перезапуск" рядом с туннелем.
- **Удаление**: Отметьте чекбокс рядом с туннелем и нажмите "Удалить выбранные".

### Добавление и редактирование туннелей

- **Добавление**: Нажмите кнопку "Добавить туннель", заполните форму и сохраните.
- **Редактирование**: Нажмите на имя туннеля, чтобы открыть форму редактирования.

**Поля формы:**

- **Имя**: Уникальное имя туннеля.
- **Хост**: Адрес SSH-сервера.
- **Порт**: Порт SSH-сервера.
- **Имя пользователя**: Имя пользователя SSH.
- **Пароль**: Пароль SSH (если используется).
- **Локальный порт**: Локальный порт для туннеля.
- **Группа**: Группа туннеля.
- **Комментарий**: Дополнительная информация.
- **Максимальное количество переподключений**: Сколько раз туннель будет пытаться переподключиться при обрыве связи.

### Просмотр логов

В разделе "Логи" отображаются последние 100 строк из лог-файла `ssh_tunnel_manager.log`. Это позволяет отслеживать ошибки и события, связанные с работой туннелей.

## Безопасность

**Важно:** Хранение паролей в открытом виде небезопасно. Рекомендуется использовать аутентификацию по SSH-ключам для повышения безопасности.

- **SSH-ключи**: Сгенерируйте пару ключей SSH и добавьте публичный ключ на сервер.
- **Отключение проверки ключа хоста**: В скрипте используются опции `-o UserKnownHostsFile=/dev/null` и `-o StrictHostKeyChecking=no`. Это снижает безопасность, но упрощает установление соединения. Используйте с осторожностью.

## Зависимости

- **Python библиотеки**:
  - `asyncio`
  - `subprocess`
  - `logging`
  - `flask`
  - `argparse`
  - `json`
- **Системные утилиты**:
  - `ssh`
  - `sshpass` (если используется аутентификация по паролю)

## Лицензия

Этот проект распространяется под лицензией MIT. Подробнее см. в файле [LICENSE](LICENSE).

## Автор

- **Ваше Имя** - [YourGitHubProfile](https://github.com/yourusername)

**Дата создания:** YYYY-MM-DD

**Контакты:** your.email@example.com

---

**Примечание:** При использовании этого скрипта убедитесь, что вы соблюдаете политики безопасности и не храните чувствительные данные в открытом виде. Всегда проверяйте настройки и конфигурации перед запуском в производственной среде.
