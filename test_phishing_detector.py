"""Тесты детектора фишинговых URL. Запуск: python test_phishing_detector.py  или pytest -v  python test_phishing_detector.py"""
import json
import sys

from phishing_detector import analyze

HG = "https://sb\u0435rbank.ru/"          # кириллическая "е" вместо латинской e

# (url, ожидаемый уровень, признаки, которые обязаны сработать)
CASES = [
    # легитимные -> LOW
    ("https://www.sberbank.ru/", "LOW", set()),
    ("https://www.gosuslugi.ru/login", "LOW", set()),
    ("https://mail.yandex.ru/", "LOW", set()),
    ("https://en.wikipedia.org/wiki/Phishing", "LOW", set()),
    ("https://github.com/login", "LOW", set()),
    ("https://президент.рф/", "LOW", set()),          # кириллический домен - не подмена
    # подозрительные -> MEDIUM
    ("http://example.com/login", "MEDIUM", {"no_https", "keywords"}),
    ("https://internationaluniversityofappliedtechnologyandmanagement.ru/", "MEDIUM", {"long_domain"}),
    ("https://a.b.c.d.example.com/", "MEDIUM", {"many_subdomains"}),
    ("http://shop.example.tk/", "MEDIUM", {"suspicious_tld", "no_https"}),
    # фишинг -> HIGH
    ("http://secure-login-bank.ru.com/verify", "HIGH", {"suspicious_tld", "no_https", "keywords"}),
    ("http://192.168.1.10/login", "HIGH", {"ip_host"}),
    ("http://3232235786/login", "HIGH", {"ip_host"}),
    ("https://sberbank-online.ru/auth", "HIGH", {"brand_in_domain"}),
    (HG, "HIGH", {"homoglyph"}),
    ("https://tinkoff.ru.com/", "HIGH", {"brand_in_domain", "suspicious_tld"}),
    ("https://google.com@evil.example.net/", "HIGH", {"userinfo"}),
    ("https://g00gle-account-verify.com/", "HIGH", {"homoglyph"}),
    ("http://paypal.com.secure-update.xyz/login", "HIGH", {"brand_in_domain"}),
    ("sberbank-online.ru", "HIGH", {"brand_in_domain"}),   # без схемы
]


def test_level_and_flags():
    for url, level, flags in CASES:
        res = analyze(url)
        assert res["risk"] == level, (url, res["risk"], level)
        assert flags <= {f["id"] for f in res["flags"]}, (url, flags)


def test_official_brand_domain_has_no_brand_flag():
    assert "brand_in_domain" not in {f["id"] for f in analyze("https://www.sberbank.ru/")["flags"]}


def test_at_least_five_heuristics_used():
    ids = set()
    for url, _, _ in CASES:
        ids |= {f["id"] for f in analyze(url)["flags"]}
    assert len(ids) >= 5


def test_invalid_input_rejected():
    for bad in ["", "   ", "http://", "a b", "http://x\x00y.ru", "http://" + "a" * 3000 + ".ru"]:
        try:
            analyze(bad)
        except ValueError:
            continue
        raise AssertionError("не отклонён ввод: %r" % bad[:30])


def test_output_does_not_keep_sensitive_url_parts():
    res = analyze("https://example.com/reset?token=SECRET123&user=ivan")
    assert "SECRET123" not in json.dumps(res, ensure_ascii=False)
    assert "ivan" not in json.dumps(res, ensure_ascii=False)


def test_result_has_required_fields():
    res = analyze("http://secure-login-bank.ru.com/verify")
    assert {"risk", "flags", "explanation", "recommendation"} <= set(res)


if __name__ == "__main__":
    fails = 0
    for url, level, flags in CASES:
        res = analyze(url)
        ok = res["risk"] == level and flags <= {f["id"] for f in res["flags"]}
        fails += not ok
        print("%-5s ожидалось %-6s получено %-6s баллы %2d  %s" %
              ("OK" if ok else "FAIL", level, res["risk"], res["score"], url))
    print("\nИтого: %d из %d пройдено" % (len(CASES) - fails, len(CASES)))
    sys.exit(1 if fails else 0)
