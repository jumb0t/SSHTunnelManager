import subprocess
import logging
import os
import sys
import shutil
import time
import signal
import traceback
from colorama import init, Fore, Style

# Инициализация colorama
init(autoreset=True)

# Конфигурационные параметры
REMOTE_HOST = "127.0.0.1"
REMOTE_PORT = 22
SSH_USER = "peter"
SSH_PASSWORD = "peter"
LOCAL_PORT = 6060
LOG_FILE = "/var/log/autossh_tunnel.log"
CONNECT_TIMEOUT = 5
SERVER_ALIVE_INTERVAL = 15
SERVER_ALIVE_COUNT_MAX = 3
COMPRESSION = "yes"
CIPHERS = "3des-cbc,aes128-cbc,aes192-cbc,aes256-cbc,aes128-ctr,aes192-ctr,aes256-ctr,aes128-gcm@openssh.com,aes256-gcm@openssh.com,chacha20-poly1305@openssh.com"
MACS = "hmac-sha1,hmac-sha1-96,hmac-sha2-256,hmac-sha2-512,hmac-md5,hmac-md5-96,umac-64@openssh.com,umac-128@openssh.com"
KEX_ALGORITHMS = "diffie-hellman-group14-sha1,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp256,ecdh-sha2-nistp384,ecdh-sha2-nistp521,curve25519-sha256,sntrup761x25519-sha512@openssh.com"

NO_HOST_KEY_CHECKING = ["-o", "UserKnownHostsFile=/dev/null", "-o", "StrictHostKeyChecking=no"]
NO_TTY = ["-T", "-N"]

process = None  # Глобальная переменная для хранения процесса

def setup_logging():
    """
    Настраивает логирование в файл и консоль.
    Проверяет доступность лог-файла для записи.
    """
    try:
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(LOG_FILE),
                logging.StreamHandler(sys.stdout)
            ]
        )
    except PermissionError:
        print(f"{Fore.RED}Нет прав на запись в лог-файл {LOG_FILE}. Используется вывод только в консоль.{Style.RESET_ALL}")
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.StreamHandler(sys.stdout)
            ]
        )

def log(message, level='INFO'):
    """
    Логирует сообщение с указанным уровнем важности и добавляет цвет в консольный вывод.
    """
    if level == 'ERROR':
        logging.error(f"{Fore.RED}{message}{Style.RESET_ALL}")
    elif level == 'DEBUG':
        logging.debug(f"{Fore.CYAN}{message}{Style.RESET_ALL}")
    elif level == 'WARNING':
        logging.warning(f"{Fore.YELLOW}{message}{Style.RESET_ALL}")
    else:
        logging.info(f"{Fore.GREEN}{message}{Style.RESET_ALL}")

def check_command(command):
    """
    Проверяет наличие команды в системе.
    """
    path = shutil.which(command)
    if path is None:
        log(f"Команда '{command}' не найдена. Установите её с помощью 'sudo apt install {command}' и попробуйте снова.", "ERROR")
        return False
    return True

def configure_connection():
    """
    Выводит текущую конфигурацию подключения.
    """
    log("Конфигурация подключения:")
    log(f"  - Хост: {REMOTE_HOST}")
    log(f"  - Порт: {REMOTE_PORT}")
    log(f"  - Пользователь: {SSH_USER}")
    log(f"  - Локальный порт SOCKS5: {LOCAL_PORT}")
    log(f"  - Параметры сжатия: {COMPRESSION}")
    log(f"  - Алгоритмы шифрования: {CIPHERS}")
    log(f"  - MAC алгоритмы: {MACS}")
    log(f"  - Алгоритмы KEX: {KEX_ALGORITHMS}")
    log(f"  - Время ожидания подключения: {CONNECT_TIMEOUT} сек.")

def kill_process():
    """
    Завершает процесс autossh, если он запущен.
    """
    global process
    if process and process.poll() is None:
        try:
            process.terminate()
            process.wait()
            log("Процесс autossh был завершен.", "INFO")
        except Exception as e:
            log(f"Не удалось завершить процесс autossh: {e}", "ERROR")
            log(traceback.format_exc(), "DEBUG")

def start_autossh():
    """
    Запускает autossh для установления SOCKS5 прокси-туннеля.
    """
    global process

    log(f"Запуск SOCKS5 прокси на локальном порту {LOCAL_PORT} с удаленным сервером {REMOTE_HOST}...")

    autossh_command = [
        'sshpass', '-p', SSH_PASSWORD, 'autossh', '-M', '0', '-N', '-D', str(LOCAL_PORT),
        '-o', f"ServerAliveInterval={SERVER_ALIVE_INTERVAL}",
        '-o', f"ServerAliveCountMax={SERVER_ALIVE_COUNT_MAX}",
        '-o', "TCPKeepAlive=yes",
        '-o', f"ConnectTimeout={CONNECT_TIMEOUT}",
        '-o', f"Compression={COMPRESSION}",
        '-o', f"Ciphers={CIPHERS}",
        '-o', f"MACs={MACS}",
        '-o', f"KexAlgorithms={KEX_ALGORITHMS}",
        '-o', "LogLevel=ERROR",
        '-o', "PasswordAuthentication=yes",
    ] + NO_HOST_KEY_CHECKING + NO_TTY + [f"{SSH_USER}@{REMOTE_HOST}", '-p', str(REMOTE_PORT)]

    try:
        process = subprocess.Popen(autossh_command, stderr=subprocess.PIPE)
        log(f"SOCKS5 прокси успешно запущен на порту {LOCAL_PORT}")
        log(f"Удаленный хост: {REMOTE_HOST}:{REMOTE_PORT}")
        log(f"Пользователь: {SSH_USER}")

        # Мониторинг вывода процесса на наличие ошибок
        while True:
            output = process.stderr.readline()
            if output:
                log(output.decode().strip(), "ERROR")
            if process.poll() is not None:
                log("Процесс autossh завершен.")
                break
            time.sleep(1)

    except subprocess.CalledProcessError as e:
        log(f"Ошибка при запуске SOCKS5 прокси: {e}", "ERROR")
        log("Проверьте ваши SSH учетные данные и сетевое соединение.", "INFO")
        log(traceback.format_exc(), "DEBUG")
    except FileNotFoundError as e:
        log(f"Команда не найдена: {e}", "ERROR")
        log("Убедитесь, что все необходимые команды установлены.", "INFO")
        log(traceback.format_exc(), "DEBUG")
    except Exception as e:
        log(f"Произошла непредвиденная ошибка: {e}", "ERROR")
        log("Обратитесь в поддержку или проверьте логи для получения дополнительной информации.", "INFO")
        log(traceback.format_exc(), "DEBUG")
    finally:
        kill_process()

def signal_handler(signum, frame):
    """
    Обработчик системных сигналов для корректного завершения работы.
    """
    log(f"Получен сигнал {signum}. Завершение работы.", "INFO")
    kill_process()
    sys.exit(0)

def main():
    """
    Главная функция запуска скрипта.
    """
    setup_logging()

    log("Проверка необходимых инструментов...")

    try:
        if not check_command('autossh'):
            sys.exit(1)

        if not check_command('sshpass'):
            sys.exit(1)

        configure_connection()

        # Обработка сигналов SIGINT и SIGTERM
        signal.signal(signal.SIGINT, signal_handler)
        signal.signal(signal.SIGTERM, signal_handler)

        # Запуск autossh
        start_autossh()

    except KeyboardInterrupt:
        log("Скрипт был прерван пользователем.", "WARNING")
        kill_process()
        sys.exit(0)
    except PermissionError as e:
        log(f"Ошибка прав доступа: {e}", "ERROR")
        log(f"Проверьте ваши права доступа для записи в {LOG_FILE} или другие ресурсы.", "INFO")
        log(traceback.format_exc(), "DEBUG")
        sys.exit(1)
    except Exception as e:
        log(f"Необработанная ошибка в основном блоке: {e}", "ERROR")
        log("Проверьте логи для получения дополнительной информации.", "INFO")
        log(traceback.format_exc(), "DEBUG")
        sys.exit(1)
    finally:
        kill_process()

if __name__ == "__main__":
    main()
