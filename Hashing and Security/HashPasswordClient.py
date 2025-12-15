import hashlib
import secrets


class HashPasswordClient:
    def __init__(self, iteration_count: int = 100000, salt_length: int = 16):
        self.iteration_count = iteration_count
        self.salt_length = salt_length

    def hash_password(self, raw_password: str) -> str:
        """Хеширует пароль с солью и возвращает строку в формате: алгоритм$итерации$соль$хеш"""
        # Генерируем случайную соль
        salt = secrets.token_hex(self.salt_length // 2)

        # Хешируем пароль с солью
        hashed = hashlib.pbkdf2_hmac(
            'sha256',
            raw_password.encode('utf-8'),
            salt.encode('utf-8'),
            self.iteration_count
        )

        # Преобразуем бинарный хеш в hex-строку
        hashed_hex = hashed.hex()

        # Возвращаем строку в формате: алгоритм$итерации$соль$хеш
        return f"sha256${self.iteration_count}${salt}${hashed_hex}"

    def validate_password(self, input_password: str, hashed_password: str) -> bool:
        """Проверяет, соответствует ли введенный пароль сохраненному хешу"""
        # Разбираем строку с хешем
        parts = hashed_password.split('$')
        if len(parts) != 4:
            return False

        algorithm, iterations_str, salt, stored_hash = parts

        # Хешируем введенный пароль с теми же параметрами
        input_hashed = hashlib.pbkdf2_hmac(
            algorithm,
            input_password.encode('utf-8'),
            salt.encode('utf-8'),
            int(iterations_str)
        )

        input_hashed_hex = input_hashed.hex()

        # Сравниваем хеши (используем constant-time сравнение для безопасности)
        return secrets.compare_digest(input_hashed_hex, stored_hash)


# Пример использования
if __name__ == "__main__":
    # Создаем клиент с настройками
    hasher = HashPasswordClient(iteration_count=100000, salt_length=16)

    # Хешируем пароль
    password = "MySecurePassword123"
    hashed = hasher.hash_password(password)
    print(f"Хешированный пароль: {hashed}")

    # Проверяем правильный пароль
    is_valid = hasher.validate_password("MySecurePassword123", hashed)
    print(f"Правильный пароль: {is_valid}")  # True

    # Проверяем неправильный пароль
    is_valid = hasher.validate_password("WrongPassword", hashed)
    print(f"Неправильный пароль: {is_valid}")  # False