# Аудит форка, 20 октября 2026 года

База: Medium1992/mihomo-proxy-ros, commit `2780b3ce2e5bfe80895e505f6e0a4616746b7639`.
Лицензия GPL-3.0 сохранена. Оригинал доступен только для чтения.

## Карта компонентов

| Компонент | Назначение |
| --- | --- |
| `entrypoint.sh` (4905 строк) | ENV → Mihomo YAML, запуск Mihomo/ByeDPI/nfqws/nfqws2, nftables или iptables, policy routing, BusyBox httpd |
| `www/cgi-bin/index.sh`, `www/ui.js` | Существующая панель, подписки, узлы, группы, файлы, генератор CLI |
| `www/cgi-bin/draft` | Черновик в tmpfs; `panel-data` сохраняет имена DNS forwarder/address list |
| `installer/parts` | Старый установщик: VETH, DNS, таблица, routes, mangle, ENV, скачивание списков |
| `Dockerfile` | Загрузка готовых ядер и DPI-компонентов, ARM v5/v7, ARM64, AMD64 v1–v4 |
| `Dockerfile-release`, `core_patches` | Сборка патченного Mihomo; fake-ip SRC-IP-CIDR и XHTTP flow |
| `/root/.config/mihomo` | Подписки и пользовательские файлы; генерируемые YAML в `/dev/shm` |

Входной интерфейс — первый VETH. TProxy перехватывает TCP/UDP внутри контейнера.
Альтернатива — redirect TCP и TUN UDP. nfqws/nfqws2 требуют NFQUEUE и доступны
на ARM64/AMD64. Запуск процесса не подтверждает работу этих механизмов.
Исходный entrypoint меняет sysctl, очищает таблицы firewall своего network namespace,
формирует policy routing, поэтому обычная проверка HTTP недостаточна.

## Проверенные официальные возможности

* Custom Apps существуют с 7.22, используют расширение Compose YAML.
* Каталог — YAML-массив по `app/settings app-store-urls`.
* Apps создают VETH, bridge attachment, NAT и именованные постоянные тома.
* Поддерживаются переменные `[containerIP]`, `[routerIP]`, `[secret:name]`.
* Port mapping: `8088:80:web`, UDP — `5353:53/udp:dns`.
* Документированный список YAML service fields **не содержит** `privileged`/`cap_add`.
  Не переносим эти поля из Docker Compose без проверки.
* Обычный `/container` в 7.24+ поддерживает `privileged`; это отдельная возможность.
* REST — Basic auth поверх HTTPS, GET/PUT/PATCH/DELETE; все значения в ответах строки.
  Транзакций и эквивалента Safe Mode для набора REST-запросов нет.
* Минимальная группа: `read,write,rest-api`. RouterOS не ограничивает `write`
  отдельными firewall-объектами; агент сам ограничивает свои операции.

## Реальный роутер: только чтение на этапе аудита

hAP ax², ARM64, RouterOS **7.23.8 long-term**, container package установлен,
device-mode container=yes, Apps настроены на USB. HTTPS использует частный CA;
системный trust store клиента его не знает. `privileged` отсутствует в proplist
7.23.8. Конфигурация роутера на этапе аудита не изменялась.

## Архитектурные ограничения

Не переносим глобальные изменения старого установщика: отключение IPv6, смену DNS/NTP,
редактирование пользовательского FastTrack. Сетевой профиль форка создаёт только свои
объекты и требует явного preview. Доступ к API, TLS и API-пользователь создаются
администратором до подключения: приложение не может безопасно само выдать себе права.
IPv6, DoH клиентов и сторонние VPN требуют отдельной политики; обещание отсутствия
всех DNS leaks без проверки всей сети было бы неверным.

## Источники

* https://manual.mikrotik.com/docs/containers/apps/
* https://manual.mikrotik.com/docs/containers/
* https://manual.mikrotik.com/docs/cli-reference/container/
* https://help.mikrotik.com/docs/spaces/ROS/pages/47579162/REST+API
* https://help.mikrotik.com/docs/spaces/ROS/pages/8978504/User
* https://manual.mikrotik.com/docs/firewall-and-quality-of-service/packet-flow-in-routeros/
