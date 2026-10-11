import csv
import functools
import hashlib
import json
import os
import sys
from datetime import datetime

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "../../")))
from shared.student import GROUP_NAME, STUDENT_NAME, VARIANT_NUMBER


class ValidationError(Exception):
    pass


SALT = str(VARIANT_NUMBER).zfill(5)

DATA_DIR = os.path.join(os.path.dirname(__file__), "data")
USERS_CSV = os.path.join(DATA_DIR, "users.csv")
LOG_JSON = os.path.join(DATA_DIR, "log.json")

users_db = []


def log_event(func):
    @functools.wraps(func)
    def wrapper(username, password, *args, **kwargs):
        result_success = False
        try:
            res = func(username, password, *args, **kwargs)
            result_success = res
            status_str = "success" if res else "failure"
        except Exception:
            status_str = "failure"
            raise
        finally:
            log_entry = {
                "event": "login",
                "user": username,
                "result": status_str,
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),  # noqa: DTZ005
                "args": list(args),
                "kwargs": kwargs,
            }
            try:
                os.makedirs(DATA_DIR, exist_ok=True)
                logs = []
                if os.path.exists(LOG_JSON):
                    with open(LOG_JSON, "r", encoding="utf-8") as f:
                        try:
                            logs = json.load(f)
                        except json.JSONDecodeError:
                            logs = []
                logs.append(log_entry)
                with open(LOG_JSON, "w", encoding="utf-8") as f:
                    json.dump(logs, f, indent=4, ensure_ascii=False)
            except (OSError, PermissionError) as log_err:
                print(
                    f"[Попередження логування]: Не вдалося записати лог - {log_err}"
                )
        return result_success

    return wrapper


def generate_hash(password: str, salt: str = "00000") -> str:
    if not password or not salt:
        raise ValueError("Пароль або сіль не можуть бути порожніми!")
    min_len = 12
    if len(password) < min_len:
        raise ValidationError(f"Пароль занадто короткий! Мінімальна довжина: {min_len}")
    combined = password + salt
    hasher = hashlib.new("sha3_512")
    hasher.update(combined.encode("utf-8"))
    return hasher.hexdigest()


def create_user(username: str, password: str):
    hashed_pwd = generate_hash(password, SALT)
    return (username, hashed_pwd)


def create_users(users_list):
    global users_db
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
        users_db = [create_user(u, p) for u, p in users_list]
        with open(USERS_CSV, mode="w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["username", "password_hash"])
            for user, pwd_hash in users_db:
                writer.writerow([user, pwd_hash])
        print(f"База даних успішно створено та записано у {USERS_CSV}")
    except (OSError, FileNotFoundError, PermissionError) as e:
        print(f"[Помилка файлу при створенні бази]: {e}")
    except ValidationError as e:
        print(f"[Помилка валідації пароля]: {e}")


def read_users_db():
    global users_db
    users_db = []
    try:
        if os.path.exists(USERS_CSV):
            with open(USERS_CSV, mode="r", encoding="utf-8") as f:
                reader = csv.reader(f)
                next(reader, None)
                for row in reader:
                    if len(row) >= 2:
                        users_db.append((row[0], row[1]))
    except (OSError, FileNotFoundError, PermissionError, csv.Error) as e:
        print(f"[Помилка читання CSV]: {e}")


@log_event
def login(username: str, password: str) -> bool:
    if not username or not password:
        raise ValueError("Логін або пароль не можуть бути порожніми при вкли!")
    read_users_db()
    input_hash = generate_hash(password, SALT)
    for db_user, db_hash in users_db:
        if db_user == username and db_hash == input_hash:
            return True
    return False


def run_task3():
    print(
        f"Студент: {STUDENT_NAME} | Група: {GROUP_NAME} | Варіант: {VARIANT_NUMBER}\n"
    )
    users_to_register = [
        ("admin_sec", "SecureAdmin#123"),
        ("analyst_01", "Pa$$w0rd2023!"),
        ("dev_master", "CodeMaster$999"),
        ("guest_user", "GuestPass1234!"),
        ("audit_pro", "AuditSecure#777"),
        ("manager_x", "ManagerKey$2026"),
        ("support_911", "SupportHelp!555"),
        ("operator_b", "OperatorLock@888"),
        ("net_admin", "NetworkPass#333"),
        ("root_guard", "SuperRootKey$111"),
    ]
    print("--- Створення бази даних користувачів ---")
    create_users(users_to_register)
    print("\n--- Зчитана таблиця бази даних з CSV ---")
    read_users_db()
    print(f"{'ЛОГІН':<15} | {'ХЕШ ПАРОЛЯ (SHA3_512)':<40}")
    print("-" * 60)
    for u, h in users_db:
        print(f"{u:<15} | {h[:38]}...")
    print("--- Тестування автентифікації та логування ---")
    try:
        res1 = login("admin_sec", "SecureAdmin#123")
        print(f"Вхід admin_sec: {'Успішно' if res1 else 'Помилка'}")
    except Exception as e:  # noqa: BLE001
        print(f"Виняток при вхді: {e}")
    try:
        res2 = login("admin_sec", "WrongPassword123")
        print(f"Вхід admin_sec (невірний пароль): {'Успішно' if res2 else 'Помилка'}")
    except Exception as e:  # noqa: BLE001
        print(f"Виняток при вхді: {e}")
    try:
        login("", "")
    except ValueError as ve:
        print(f"Очікуваний ValueError спіймано: {ve}")
    try:
        login("analyst_01", "short")
    except ValidationError as ve:
        print(f"Очікуваний ValidationError спіймано: {ve}")


if __name__ == "__main__":
    run_task3()