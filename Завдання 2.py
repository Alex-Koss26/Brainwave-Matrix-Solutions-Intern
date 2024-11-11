import re
import hashlib
import json
import os
import secrets
import string
from datetime import datetime, timedelta
import math

PASSWORD_HISTORY_FILE = "password_history.json"
COMMON_PASSWORDS = [
    "password", "123456", "123456789", "qwerty", "abc123", "football", 
    "monkey", "letmein", "dragon", "111111", "baseball", "iloveyou", 
    "trustno1", "1234567", "sunshine", "master", "123123", "welcome", 
    "shadow", "ashley", "jesus", "michael", "ninja", "mustang", "password1"
]

def load_password_history():
    if os.path.exists(PASSWORD_HISTORY_FILE):
        with open(PASSWORD_HISTORY_FILE, 'r') as file:
            return json.load(file)
    return []

def save_password_history(history):
    with open(PASSWORD_HISTORY_FILE, 'w') as file:
        json.dump(history, file, indent=4)

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def is_password_reused(password, history):
    hashed = hash_password(password)
    return hashed in history

def add_password_to_history(password, history, max_history=5):
    hashed = hash_password(password)
    history.append({
        "password": hashed,
        "date_set": datetime.now().isoformat()
    })
    if len(history) > max_history:
        history.pop(0)
    save_password_history(history)

def calculate_entropy(password):
    pool = sum([
        26 if any(c.islower() for c in password) else 0,
        26 if any(c.isupper() for c in password) else 0,
        10 if any(c.isdigit() for c in password) else 0,
        len(string.punctuation) if any(not c.isalnum() for c in password) else 0
    ])
    entropy = len(password) * math.log2(pool) if pool > 0 else 0
    return round(entropy, 2)

def generate_strong_password(length=12):
    if length < 8:
        length = 8
    password_chars = [
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.digits),
        secrets.choice(string.punctuation)
    ]
    password_chars += [secrets.choice(string.ascii_letters + string.digits + string.punctuation) for _ in range(length - 4)]
    secrets.SystemRandom().shuffle(password_chars)
    return ''.join(password_chars)

def check_password_strength(password, username, personal_data):
    recommendations = []
    history = load_password_history()

    # Перевірка довжини
    if len(password) < 8:
        recommendations.append("Збільшіть довжину пароля до 8 або більше символів.")

    # Перевірка складності
    has_upper = any(c.isupper() for c in password)
    has_lower = any(c.islower() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_special = any(not c.isalnum() for c in password)

    # Оцінка сили пароля
    if has_upper and has_lower and has_digit and has_special and len(password) >= 12:
        strength = "Дуже сильний пароль"
    elif has_upper and has_lower and has_digit:
        strength = "Сильний пароль"
    elif (has_upper or has_lower) and has_digit:
        strength = "Середній пароль"
    else:
        strength = "Слабкий пароль"

    # Додаткові рекомендації
    if not has_upper:
        recommendations.append("Додайте хоча б одну велику літеру.")
    if not has_lower:
        recommendations.append("Додайте хоча б одну маленьку літеру.")
    if not has_digit:
        recommendations.append("Додайте хоча б одну цифру.")
    if not has_special:
        recommendations.append("Додайте хоча б один спеціальний символ (наприклад, !, @, #, $).")

    # Перевірка на прості паролі
    if password.lower() in COMMON_PASSWORDS:
        recommendations.append("Не використовуйте поширені паролі.")

    # Перевірка на ім'я користувача
    if username and username.lower() in password.lower():
        recommendations.append("Пароль не повинен містити ваше ім'я користувача.")

    # Перевірка на персональні дані
    for data in personal_data:
        if data.lower() in password.lower():
            recommendations.append(f"Пароль не повинен містити ваші персональні дані: '{data}'.")

    # Перевірка на повторювані символи
    if re.search(r"(.)\1\1", password):  # Три або більше однакових символів підряд
        recommendations.append("Уникайте використання однакових символів поспіль.")

    # Оцінка ентропії
    entropy = calculate_entropy(password)
    if entropy < 50:
        recommendations.append("Збільшіть ентропію пароля для підвищення його стійкості.")
    entropy_info = f"Ентропія пароля: {entropy} біт"

    # Перевірка історії паролів
    if is_password_reused(password, [entry['password'] for entry in history]):
        recommendations.append("Цей пароль вже використовувався раніше. Виберіть інший пароль.")

    # Перевірка на застарілі паролі (наприклад, не старше 90 днів)
    if any(datetime.now() - datetime.fromisoformat(entry['date_set']) > timedelta(days=90) for entry in history):
        recommendations.append("Ваш попередній пароль застарілий. Рекомендується змінити пароль.")

    return strength, recommendations, entropy_info

def main():
    print("=== Перевірка Сили Пароля ===\n")
    username = input("Введіть ваше ім'я користувача: ").strip()
    personal_data = []
    if input("Чи хочете ви додати персональні дані для перевірки пароля? (y/n): ").strip().lower() == 'y':
        while True:
            data = input("Введіть персональну інформацію або натисніть Enter для завершення: ").strip()
            if not data:
                break
            personal_data.append(data)

    history = load_password_history()

    while True:
        print("\nВиберіть опцію:")
        print("1. Перевірити пароль")
        print("2. Згенерувати надійний пароль")
        print("3. Вийти")
        choice = input("Ваш вибір: ").strip()

        if choice == '1':
            password = input("Введіть пароль для перевірки (або 'exit' для виходу): ")
            if password.lower() == "exit":
                break

            strength, recommendations, entropy_info = check_password_strength(password, username, personal_data)
            print(f"\nРезультат перевірки: {strength}")
            print(entropy_info)
            if recommendations:
                print("Рекомендації для покращення пароля:")
                for rec in recommendations:
                    print(f"- {rec}")
            else:
                print("Ваш пароль дуже сильний!")

            # Якщо пароль прийнятний, додаємо його до історії
            if strength in ["Сильний пароль", "Дуже сильний пароль"] and not recommendations:
                add_password_to_history(password, history)
        elif choice == '2':
            try:
                length = int(input("Введіть бажану довжину пароля (мінімум 8): ").strip())
                if length < 8:
                    print("Довжина пароля повинна бути не менше 8 символів. Встановлено довжину 12.")
                    length = 12
            except ValueError:
                print("Невірний ввід. Встановлено довжину 12.")
                length = 12
            generated_password = generate_strong_password(length)
            print(f"\nЗгенерований надійний пароль: {generated_password}")
            add_password_to_history(generated_password, history)
        elif choice == '3':
            print("Вихід з програми.")
            break
        else:
            print("Невірний вибір. Будь ласка, оберіть опцію 1, 2 або 3.")

if __name__ == "__main__":
    main()
