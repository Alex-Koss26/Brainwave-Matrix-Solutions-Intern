import re
import urllib.parse

# Функція для перевірки формату URL
def is_valid_url(url):
    try:
        result = urllib.parse.urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

# Функція для перевірки HTTPS
def is_https(url):
    return urllib.parse.urlparse(url).scheme == 'https'

# Функція для перевірки IP-адреси в URL
def contains_ip(url):
    domain = urllib.parse.urlparse(url).netloc
    ip_pattern = re.compile(r'(\d{1,3}\.){3}\d{1,3}')
    return ip_pattern.match(domain)

# Функція для перевірки кириличних символів у домені
def contains_cyrillic(url):
    domain = urllib.parse.urlparse(url).netloc
    return bool(re.search(r'[а-яА-ЯёЁ]', domain))

# Функція для перевірки змішаних символів (латиниця + кирилиця)
def contains_mixed_characters(url):
    domain = urllib.parse.urlparse(url).netloc
    cyrillic_chars = bool(re.search(r'[а-яА-ЯёЁ]', domain))
    latin_chars = bool(re.search(r'[a-zA-Z]', domain))
    return cyrillic_chars and latin_chars

# Перевірка коротких URL
def is_short_url(url):
    short_url_services = ['bit.ly', 't.co', 'goo.gl', 'tinyurl.com']
    domain = urllib.parse.urlparse(url).netloc
    return any(service in domain for service in short_url_services)

# Функція для перевірки на фішингові ознаки
def is_phishing_url(url):
    domain = urllib.parse.urlparse(url).netloc
    
    # Перевірка на HTTPS
    if not is_https(url):
        print("WARNING: URL does not use HTTPS.")
        return True
    
    # Перевірка на IP в URL
    if contains_ip(url):
        print("WARNING: URL contains an IP address instead of a domain name.")
        return True

    # Перевірка на кириличні символи
    if contains_cyrillic(url):
        print("WARNING: URL contains Cyrillic characters, could be phishing.")
        return True
    
    # Перевірка на змішані символи
    if contains_mixed_characters(url):
        print("WARNING: URL contains mixed Cyrillic and Latin characters.")
        return True

    # Перевірка на короткий URL
    if is_short_url(url):
        print("WARNING: Shortened URL detected, could be phishing.")
        return True

    return False

# Функція сканування URL
def scan_url(url):
    if not is_valid_url(url):
        print(f"Invalid URL format: {url}")
        return

    print(f"\nScanning URL: {url}")
    
    if is_phishing_url(url):
        print("WARNING: This URL might be a phishing link!")
    else:
        print("This URL seems safe (based on basic checks).")

# Основна функція для сканування кількох URL
def main():
    print("Phishing Link Scanner\n")
    
    while True:
        urls = input("\nEnter URLs to scan (separate multiple URLs with commas, or type 'exit' to quit): ")
        
        if urls.lower() == 'exit':
            print("Exiting...")
            break

        url_list = [url.strip() for url in urls.split(',') if url.strip()]

        for url in url_list:
            scan_url(url)

# Запуск програми
if __name__ == "__main__":
    main()
