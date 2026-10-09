# Детектор фишинговых URL (вариант 1)

Консольный инструмент на Python 3.10+: по URL выдаёт оценку риска фишинга **LOW / MEDIUM / HIGH**, список сработавших признаков и понятную рекомендацию. Работает офлайн, только стандартная библиотека (`urllib.parse`, `re`, `ipaddress`, `json`).

## Файлы

- `phishing_detector.py` - программа.
- `test_phishing_detector.py` - тесты (20 URL + проверки ввода и безопасности).

## Запуск

```
python phishing_detector.py "http://secure-login-bank.ru.com/verify"
python phishing_detector.py "http://secure-login-bank.ru.com/verify" --json
python phishing_detector.py --demo
python test_phishing_detector.py        # тесты (или: pytest -v)
```

Пример вывода:

```
Домен: secure-login-bank.ru.com
Оценка риска: HIGH (сумма баллов: 5)
Сработавшие признаки:
  - [MEDIUM, +2] suspicious_tld: Необычное окончание адреса (.ru.com) - так маскируют поддельные сайты.
  - [LOW, +1] no_https: Соединение не защищено: адрес начинается с http, а не https.
  - [LOW, +1] special_chars: В адресе несколько дефисов (2) - так часто собирают «правдоподобные» адреса.
  - [LOW, +1] keywords: В адресе есть слова, типичные для кражи паролей: login, verify, secure.
Пояснение: Необычное окончание адреса (.ru.com) - так маскируют поддельные сайты. Соединение не защищено: ...
Рекомендация: Скорее всего, это фишинг. Не переходите по ссылке, не вводите логин, пароль и данные карты, ...
```

## Эвристики и веса

Веса: low = 1 балл, medium = 2, high = 4.

| Признак (`id`) | Вес | Почему подозрительно |
|---|---|---|
| `long_domain` | medium | домен длиннее 45 символов прячет настоящее имя среди «служебных» слов |
| `ip_host` | high | вместо домена IP (в т.ч. десятичный `3232235786`) - временный сервер злоумышленника |
| `homoglyph` | high | кириллица/греческий вперемешку с латиницей, `0` вместо `o` в имени бренда: глазом не отличить |
| `brand_in_domain` | high | название бренда (sber, tinkoff, gosuslugi, paypal...) в домене, который бренду не принадлежит |
| `suspicious_tld` | medium / low | `.ru.com`, `.com.com`, `.online.pro` маскируются под знакомую зону (medium); дешёвые зоны `.tk`, `.xyz` и т.п. (low) |
| `many_subdomains` | medium | 4+ уровня поддоменов: настоящий домен уходит за край строки браузера |
| `no_https` | low | нет шифрования; не доказывает фишинг, поэтому вес низкий |
| `special_chars` | low / medium | 2-3 дефиса (low), 4+ дефисов, `_` или дефис на краю части домена (medium) |
| `userinfo` | high | `google.com@evil.net`: браузер игнорирует часть до `@` |
| `keywords` | low | `login`, `verify`, `secure`, `update`... в хосте или пути |

**Итоговая оценка:** сумма баллов ≥ 4 - HIGH, 2-3 - MEDIUM, 0-1 - LOW. Поэтому один «high» признак сразу даёт HIGH, один «medium» - MEDIUM, а «low» признаки лишь складываются (`http` + слово `login` = MEDIUM).

## Безопасность реализации

- Никаких внешних запросов: всё считается локально.
- Ввод проверяется: пустая строка, пробелы и управляющие символы, длина более 2048 символов - отклоняются с понятной ошибкой (код выхода 2).
- Из URL используются только схема, домен и путь; запрос (`?token=...`), фрагмент и логин из URL в результат **не попадают** и нигде не сохраняются. URL не пишется в лог и не хранится в глобальных переменных.
- Кодировка: Unicode-домены и punycode (`xn--`) разбираются штатно, вывод принудительно в UTF-8.

## Результаты тестирования (20 примеров)

| № | URL | Ожидалось | Получено | Баллы | Сработавшие признаки |
|---|---|---|---|---|---|
| 1 | `https://www.sberbank.ru/` | LOW | LOW | 0 | - |
| 2 | `https://www.gosuslugi.ru/login` | LOW | LOW | 1 | keywords |
| 3 | `https://mail.yandex.ru/` | LOW | LOW | 0 | - |
| 4 | `https://en.wikipedia.org/wiki/Phishing` | LOW | LOW | 0 | - |
| 5 | `https://github.com/login` | LOW | LOW | 1 | keywords |
| 6 | `https://президент.рф/` | LOW | LOW | 0 | - |
| 7 | `http://example.com/login` | MEDIUM | MEDIUM | 2 | no_https, keywords |
| 8 | `https://internationaluniversityofappliedtechnologyandmanagement.ru/` | MEDIUM | MEDIUM | 2 | long_domain |
| 9 | `https://a.b.c.d.example.com/` | MEDIUM | MEDIUM | 2 | many_subdomains |
| 10 | `http://shop.example.tk/` | MEDIUM | MEDIUM | 2 | suspicious_tld, no_https |
| 11 | `http://secure-login-bank.ru.com/verify` | HIGH | HIGH | 5 | suspicious_tld, no_https, special_chars, keywords |
| 12 | `http://192.168.1.10/login` | HIGH | HIGH | 6 | ip_host, no_https, keywords |
| 13 | `http://3232235786/login` | HIGH | HIGH | 6 | ip_host, no_https, keywords |
| 14 | `https://sberbank-online.ru/auth` | HIGH | HIGH | 5 | brand_in_domain, keywords |
| 15 | `https://sbеrbank.ru/ (кириллическая «е»)` | HIGH | HIGH | 4 | homoglyph |
| 16 | `https://tinkoff.ru.com/` | HIGH | HIGH | 6 | brand_in_domain, suspicious_tld |
| 17 | `https://google.com@evil.example.net/` | HIGH | HIGH | 4 | userinfo |
| 18 | `https://g00gle-account-verify.com/` | HIGH | HIGH | 6 | homoglyph, special_chars, keywords |
| 19 | `http://paypal.com.secure-update.xyz/login` | HIGH | HIGH | 7 | brand_in_domain, suspicious_tld, no_https, keywords |
| 20 | `sberbank-online.ru` | HIGH | HIGH | 4 | brand_in_domain |

Итог: **20 из 20** примеров классифицированы верно; дополнительно проверены: отклонение некорректного ввода, отсутствие чувствительных частей URL в выводе, использование не менее 5 разных эвристик (используются все 10).

## Ограничения

Это учебный инструмент на эвристиках: список брендов и «рискованных» зон небольшой, реальный фишинг может не сработать, а редкий легитимный сайт - дать ложное срабатывание (например, `sbermarket.ru` добавлен в официальные домены Сбера вручную). Для промышленного использования нужны актуальные базы доменов (Public Suffix List, репутационные сервисы).

## Связь с защитой ПДн

Фишинг - один из главных способов получить логины и пароли сотрудников и клиентов, а через них - доступ к персональным данным (152-ФЗ). Модуль можно встроить в почтовый шлюз или плагин проверки ссылок: сотрудник без ИТ-подготовки получает простое объяснение и рекомендацию.
