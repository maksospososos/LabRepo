#!/usr/bin/env python3
"""Детектор фишинговых URL (вариант 1).

Работает полностью офлайн, только стандартная библиотека Python 3.10+.
Фишинг - это поддельный сайт, который выглядит как настоящий и выманивает
логины, пароли и данные карт. Утечка таких данных = компрометация учётных
записей и персональных данных (152-ФЗ). Здесь URL оценивается по набору
простых эвристик; каждая имеет вес (low / medium / high).

Запуск:
    python phishing_detector.py "http://secure-login-bank.ru.com/verify"
    python phishing_detector.py "<url>" --json
    python phishing_detector.py --demo
"""
import argparse
import ipaddress
import json
import re
import sys
from urllib.parse import urlsplit

# --- Веса и пороги ----------------------------------------------------------
# Веса признаков: один "high" признак сам по себе даёт HIGH, один "medium" -
# MEDIUM, "low" - лишь добавляет подозрительности.
WEIGHTS = {"low": 1, "medium": 2, "high": 4}
HIGH_THRESHOLD = 4     # сумма >= 4  -> HIGH
MEDIUM_THRESHOLD = 2   # сумма 2..3  -> MEDIUM, меньше -> LOW
MAX_URL_LEN = 2048     # защита от слишком длинного ввода
LONG_DOMAIN = 45       # длиннее - подозрительно
MANY_SUBDOMAINS = 4    # 4+ уровней поддоменов

# --- Справочники (учебный минимум) ------------------------------------------
# бренд -> (написания в домене, официальные домены)
BRANDS = {
    "Сбербанк": (("sber", "sberbank", "sbrf"),
                 ("sberbank.ru", "sber.ru", "sbrf.ru", "sbermarket.ru", "sberdevices.ru")),
    "Тинькофф/Т-Банк": (("tinkoff",), ("tinkoff.ru", "tbank.ru", "tinkoff.com")),
    "Госуслуги": (("gosuslugi",), ("gosuslugi.ru",)),
    "ВТБ": (("vtb",), ("vtb.ru", "vtb.com")),
    "Альфа-Банк": (("alfabank",), ("alfabank.ru",)),
    "Яндекс": (("yandex",), ("yandex.ru", "yandex.com", "yandex.net", "yandex.by", "yandex.kz", "ya.ru")),
    "VK": (("vk",), ("vk.com", "vk.ru", "vk.me")),
    "Ozon": (("ozon",), ("ozon.ru",)),
    "Wildberries": (("wildberries",), ("wildberries.ru",)),
    "PayPal": (("paypal",), ("paypal.com",)),
    "Google": (("google",), ("google.com", "google.ru")),
    "Apple": (("apple",), ("apple.com", "icloud.com")),
    "Microsoft": (("microsoft",), ("microsoft.com", "live.com", "office.com")),
}

# Составные "зоны", которыми маскируют фишинг (похоже на .ru, но это .com)
SUSPICIOUS_COMBOS = {"ru.com", "com.com", "net.com", "org.com", "us.com",
                     "de.com", "ru.net", "online.pro", "site.pro"}
# Зоны, популярные у одноразовых мошеннических сайтов (бесплатные/дешёвые)
RISKY_TLDS = {"tk", "ml", "ga", "cf", "gq", "xyz", "top", "click", "work", "zip"}
# Двухуровневые легитимные суффиксы (для подсчёта поддоменов без tldextract)
TWO_PART_SUFFIXES = {"co.uk", "com.ru", "org.ru", "com.br", "com.au", "co.jp"}

# Слова, типичные для страниц кражи паролей
KEYWORDS = ("login", "signin", "verify", "secure", "update",
            "confirm", "account", "password", "auth", "wallet")

# Символы-двойники: кириллица/греческий -> латиница
HOMOGLYPHS = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y",
    "і": "i", "ј": "j", "ѕ": "s", "ԁ": "d", "к": "k", "м": "m", "т": "t",
    "н": "h", "в": "b", "ο": "o", "α": "a", "ν": "v", "ρ": "p",
})
# Цифры, похожие на буквы: 0->o, 3->e, 5->s ("1" обрабатывается отдельно: i или l)
DIGIT_LOOKALIKES = str.maketrans({"0": "o", "3": "e", "5": "s", "4": "a", "7": "t"})

# --- Человекочитаемые тексты -------------------------------------------------
RECOMMENDATIONS = {
    "HIGH": "Скорее всего, это фишинг. Не переходите по ссылке, не вводите логин, "
            "пароль и данные карты, сообщите о ссылке в службу информационной безопасности.",
    "MEDIUM": "Ссылка вызывает сомнения. Не вводите пароли, пока не проверите адрес: "
              "откройте сайт, набрав адрес вручную или через закладку.",
    "LOW": "Явных признаков фишинга не найдено, но перед вводом пароля всё равно "
           "проверьте адрес сайта в строке браузера.",
}


# --- Разбор URL ---------------------------------------------------------------
def parse_url(raw):
    """Проверяет ввод и возвращает (схема, хост, путь, есть_userinfo).

    Запрос и фрагмент (?token=...) намеренно отбрасываются и дальше не
    используются: в них часто лежат чувствительные данные.
    """
    if not isinstance(raw, str):
        raise ValueError("URL должен быть строкой")
    url = raw.strip()
    if not url:
        raise ValueError("Пустой URL")
    if len(url) > MAX_URL_LEN:
        raise ValueError("URL слишком длинный (больше %d символов)" % MAX_URL_LEN)
    if re.search(r"[\x00-\x20\x7f]", url):
        raise ValueError("В URL есть пробелы или управляющие символы")
    try:
        parts = urlsplit(url if "://" in url else "//" + url)
        host = parts.hostname
        has_userinfo = "@" in parts.netloc
        scheme = parts.scheme.lower() if "://" in url else ""
        path = parts.path
    except ValueError as exc:
        raise ValueError("Некорректный URL: %s" % exc) from None
    if not host:
        raise ValueError("В URL не найден домен")
    host = _decode_idn(host.rstrip(".").lower())
    return scheme, host, path.lower(), has_userinfo


def _decode_idn(host):
    """xn--... (punycode) -> читаемый Unicode, чтобы увидеть подмену символов."""
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                label = label.encode("ascii").decode("idna")
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def _is_ip(host):
    """IP в обычном, десятичном (3232235786) или шестнадцатеричном виде."""
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return bool(re.fullmatch(r"\d{8,10}|0x[0-9a-f]+", host))


def _is_official(host, domains):
    return any(host == d or host.endswith("." + d) for d in domains)


def _brand_variants(host):
    """Варианты написания хоста после замены символов-двойников."""
    base = host.translate(HOMOGLYPHS).translate(DIGIT_LOOKALIKES)
    return {base.replace("1", "i"), base.replace("1", "l")}


def _brand_in(text, aliases):
    tokens = re.split(r"[.\-]", text)
    # короткие бренды (vk, vtb) ищем только как отдельное слово, чтобы не ловить "travkin"
    return any((a in text) if len(a) >= 4 else (a in tokens) for a in aliases)


def find_brand(host):
    """Возвращает (бренд, найден_только_после_замены_символов) или None.

    Бренд в домене подозрителен, только если сайт НЕ принадлежит самому бренду.
    """
    for name, (aliases, official) in BRANDS.items():
        if _is_official(host, official):
            continue
        if _brand_in(host, aliases):
            return name, False
        if any(_brand_in(v, aliases) for v in _brand_variants(host)):
            return name, True
    return None


def _mixed_script(host):
    """Есть ли в одной части домена одновременно латиница и кириллица/греческий."""
    for label in host.split("."):
        scripts = set()
        for ch in label:
            if not ch.isalpha():
                continue
            if ch.isascii():
                scripts.add("latin")
            elif "\u0400" <= ch <= "\u04ff":
                scripts.add("cyrillic")
            elif "\u0370" <= ch <= "\u03ff":
                scripts.add("greek")
        if "latin" in scripts and len(scripts) > 1:
            return True
    return False


# --- Эвристики -------------------------------------------------------------------
# Каждая возвращает None или (вес, id, описание для пользователя).
def check_long_domain(ctx):
    # Очень длинный домен прячет настоящее имя среди "служебных" слов
    # (my-bank-secure-login-update-account...) и усыпляет бдительность.
    if len(ctx["host"]) > LONG_DOMAIN:
        return "medium", "long_domain", \
            "Адрес сайта необычно длинный (%d символов) - так часто прячут настоящее имя." % len(ctx["host"])


def check_ip_host(ctx):
    # Легитимные сервисы работают на доменах; IP вместо домена - признак
    # временного сервера злоумышленника, у которого нет своего имени.
    if ctx["is_ip"]:
        return "high", "ip_host", \
            "Вместо названия сайта указан IP-адрес - у настоящих сервисов так почти не бывает."


def check_homoglyph(ctx):
    # Подмена символов: русская "а" вместо латинской a, 0 вместо o и т.п.
    # Глаз их не отличает, а для браузера это другой сайт.
    if ctx["is_ip"]:
        return None
    brand = ctx["brand"]
    if _mixed_script(ctx["host"]) or (brand and brand[1]):
        return "high", "homoglyph", \
            "В адресе используются похожие по виду символы (например, русская «а» вместо " \
            "латинской a или 0 вместо o), чтобы выдать сайт за известный."


def check_brand(ctx):
    # Имя известного бренда в чужом домене (sberbank-online.ru) - классика
    # фишинга: жертва видит знакомое слово и не проверяет остальное.
    brand = ctx["brand"]
    if brand and not brand[1]:
        return "high", "brand_in_domain", \
            "В адресе есть название известной компании (%s), но сайт ей не принадлежит." % brand[0]


def check_tld(ctx):
    # .ru.com / .com.com выглядят как "почти .ru", но это обычная зона .com,
    # которую может купить кто угодно. Дешёвые зоны (.tk, .xyz) любят для
    # одноразовых фишинговых сайтов.
    if ctx["is_ip"]:
        return None
    labels = ctx["labels"]
    combo = ".".join(labels[-2:])
    if combo in SUSPICIOUS_COMBOS:
        return "medium", "suspicious_tld", \
            "Необычное окончание адреса (.%s) - так маскируют поддельные сайты." % combo
    if labels[-1] in RISKY_TLDS:
        return "low", "suspicious_tld", \
            "Окончание адреса .%s часто используют для одноразовых мошеннических сайтов." % labels[-1]


def check_subdomains(ctx):
    # Фишеры нагромождают поддомены: bank.login.secure.example.com, чтобы
    # в узкой строке (особенно на телефоне) был виден только "правильный" кусок.
    if ctx["is_ip"]:
        return None
    labels = ctx["labels"]
    suffix_len = 3 if ".".join(labels[-2:]) in TWO_PART_SUFFIXES else 2
    n = max(0, len(labels) - suffix_len)
    if n >= MANY_SUBDOMAINS:
        return "medium", "many_subdomains", \
            "Слишком много «приставок» перед основным доменом (%d) - адрес запутывают намеренно." % n


def check_no_https(ctx):
    # Без HTTPS данные идут открыто. Само по себе не доказывает фишинг
    # (много старых легитимных сайтов), поэтому вес низкий.
    if ctx["scheme"] == "http":
        return "low", "no_https", "Соединение не защищено: адрес начинается с http, а не https."


def check_special_chars(ctx):
    # Много дефисов: login-secure-bank-verify.com - так "собирают" правдоподобный
    # адрес из слов. Дефис в начале/конце части и символ "_" в домене - не норма.
    if ctx["is_ip"]:
        return None
    host = ctx["host"]
    hyphens = host.count("-")
    odd = "_" in host or any(l.startswith("-") or l.endswith("-") for l in ctx["labels"])
    if hyphens >= 4 or odd:
        return "medium", "special_chars", "В адресе слишком много дефисов или есть необычные символы."
    if hyphens >= 2:
        return "low", "special_chars", "В адресе несколько дефисов (%d) - так часто собирают «правдоподобные» адреса." % hyphens


def check_userinfo(ctx):
    # http://google.com@evil.net/: браузер считает "google.com" логином, а
    # реальный сайт - evil.net. Лёгкий способ обмануть невнимательного человека.
    if ctx["userinfo"]:
        return "high", "userinfo", \
            "В адресе есть символ «@»: всё, что до него, браузер игнорирует, реальный сайт указан после него."


def check_keywords(ctx):
    # Слова login/verify/secure в адресе - приманка "срочно подтвердите данные".
    # Встречаются и на честных сайтах, поэтому вес низкий.
    text = ctx["host"] + ctx["path"]
    found = [w for w in KEYWORDS if w in text]
    if found:
        return "low", "keywords", "В адресе есть слова, типичные для кражи паролей: %s." % ", ".join(found[:3])


HEURISTICS = (check_long_domain, check_ip_host, check_homoglyph, check_brand, check_tld,
              check_subdomains, check_no_https, check_special_chars, check_userinfo, check_keywords)


# --- Оценка ------------------------------------------------------------------------
def risk_level(score):
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def analyze(url):
    """Анализирует URL и возвращает словарь с оценкой. Ничего не пишет на диск."""
    scheme, host, path, userinfo = parse_url(url)
    is_ip = _is_ip(host)
    ctx = {"scheme": scheme, "host": host, "path": path, "userinfo": userinfo,
           "labels": host.split("."), "is_ip": is_ip,
           "brand": None if is_ip else find_brand(host)}
    flags = []
    for check in HEURISTICS:
        res = check(ctx)
        if res:
            weight, fid, text = res
            flags.append({"id": fid, "weight": weight, "points": WEIGHTS[weight], "description": text})
    score = sum(f["points"] for f in flags)
    level = risk_level(score)
    top = sorted(flags, key=lambda f: -f["points"])[:2]
    if top:
        explanation = " ".join(f["description"] for f in top)
    else:
        explanation = "Подозрительных особенностей в адресе не обнаружено."
    # В результат попадает только домен: путь, запрос и логин из URL не сохраняются.
    return {"domain": host, "risk": level, "score": score, "flags": flags,
            "explanation": explanation, "recommendation": RECOMMENDATIONS[level]}


def format_text(res):
    lines = ["Домен: %s" % res["domain"],
             "Оценка риска: %s (сумма баллов: %d)" % (res["risk"], res["score"]),
             "Сработавшие признаки:"]
    if res["flags"]:
        for f in res["flags"]:
            lines.append("  - [%s, +%d] %s: %s" % (f["weight"].upper(), f["points"], f["id"], f["description"]))
    else:
        lines.append("  - нет")
    lines.append("Пояснение: %s" % res["explanation"])
    lines.append("Рекомендация: %s" % res["recommendation"])
    return "\n".join(lines)


DEMO_URLS = (
    "https://www.sberbank.ru/",
    "http://secure-login-bank.ru.com/verify",
    "https://sberbank-online.ru/auth",
    "http://192.168.1.10/login",
    "https://google.com@evil.example.net/",
)


def main(argv=None):
    if hasattr(sys.stdout, "reconfigure"):          # корректный вывод кириллицы
        sys.stdout.reconfigure(encoding="utf-8")
    ap = argparse.ArgumentParser(description="Оценка риска фишинга по URL (офлайн)")
    ap.add_argument("url", nargs="?", help="проверяемый URL")
    ap.add_argument("--json", action="store_true", help="вывод в формате JSON")
    ap.add_argument("--demo", action="store_true", help="показать примеры")
    args = ap.parse_args(argv)
    urls = DEMO_URLS if args.demo else [args.url if args.url else input("Введите URL: ")]
    code = 0
    for u in urls:
        try:
            res = analyze(u)
        except ValueError as exc:
            print("Ошибка: %s" % exc)
            code = 2
            continue
        print(json.dumps(res, ensure_ascii=False, indent=2) if args.json else format_text(res))
        print()
    return code


if __name__ == "__main__":
    sys.exit(main())
