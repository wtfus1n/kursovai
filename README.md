# Атаки на AODV и OLSR в NS-3.49

Восемь патчей для моделирования атак на маршрутизацию в мобильных самоорганизующихся сетях. Для каждой пары «протокол — атака» есть отдельный патч и контрольный сценарий.

**NS-3.49 · Linux / WSL · 8 патчей · 20 контрольных прогонов**

[Скачать ZIP](https://github.com/wtfus1n/kursovai/archive/refs/heads/main.zip) · [Патчи](#патчи) · [Быстрый старт](#быстрый-старт) · [Результаты](#результаты-проверок) · [Устройство реализации](#устройство-реализации)

## Патчи

| Атака | AODV | OLSR |
| --- | --- | --- |
| Чёрная дыра | [Blackhole](patches/ns3-49-aodv-blackhole.patch) | [Blackhole](patches/ns3-49-olsr-blackhole.patch) |
| Серая дыра | [Grayhole](patches/ns3-49-aodv-grayhole.patch) | [Grayhole](patches/ns3-49-olsr-grayhole.patch) |
| Туннель | [Wormhole](patches/ns3-49-aodv-wormhole.patch) | [Wormhole](patches/ns3-49-olsr-wormhole.patch) |
| «Сивилла» | [Sybil](patches/ns3-49-aodv-sybil.patch) | [Sybil](patches/ns3-49-olsr-sybil.patch) |

> [!IMPORTANT]
> Каждый патч применяется к отдельной копии чистых исходников **NS-3.49**. Скрипт подготовки сверяет версию и SHA-256, выполняет пробное применение и переносит сценарий в `scratch/`.

## Быстрый старт

Установите Python 3, GNU Patch, компилятор C++, CMake и Ninja либо Make. Требования к инструментам указаны в [инструкции по сборке NS-3.49](https://gitlab.com/nsnam/ns-3-dev/-/blob/ns-3.49/doc/installation/source/quick-start.rst).

**1. Скачайте комплект и подготовьте копию с чёрной дырой AODV.**

```bash
git clone https://github.com/wtfus1n/kursovai.git ns3-attacks
cd ns3-attacks

# Укажите путь к вашим чистым исходникам NS-3.49.
source_dir="$HOME/ns3-work/ns-3.49"
work_dir="$HOME/ns3-work/check-aodv-blackhole"

python3 patches/prepare_variant.py "$source_dir" "$work_dir" \
  --protocol aodv --attack blackhole
```

Папка `work_dir` должна быть новой. Если исходников ещё нет, скачайте [релиз NS-3.49](https://www.nsnam.org/releases/) или возьмите [официальный тег](https://gitlab.com/nsnam/ns-3-dev/-/tree/ns-3.49).

**2. Соберите и запустите сценарий с выключенной и включённой атакой.**

```bash
cd "$work_dir"
./ns3 configure --enable-modules=aodv,wifi,mobility,applications \
  --disable-python-bindings
./ns3 build aodv-drop-check -j 4
./ns3 run 'aodv-drop-check --malicious=0'
./ns3 run 'aodv-drop-check --malicious=1'
```

В строках с результатом поле `received` меняется с **300** на **0**, а `localReceived` равно **10** в обоих прогонах. Значения `--protocol`, `--attack` и команды для остальных вариантов собраны в [справочнике по запуску](patches/README.md).

## Результаты проверок

Все восемь вариантов прошли пробное применение, сборку и контрольные сценарии в WSL. В таблице приведены результаты при фиксированных настройках каждого сценария.

| Атака | AODV | OLSR |
| --- | --- | --- |
| Чёрная дыра | Доставка транзита снизилась с 300 до 0 пакетов. Самому нарушителю доставлено 10 из 10. | Доставлено 100 из 300 пакетов. Эти 100 отправлены до `AttackStart`. |
| Серая дыра | При `p = 0 / 0,5 / 1` доставлено 299 / 151 / 0 из 300. | При тех же значениях `p` доставлено 300 / 152 / 0 из 300. Измеряемый поток начинается одновременно с отбрасыванием на 20-й секунде. |
| Туннель | С обычным каналом и туннелем доставлено по 6400 байт. Объявленная длина маршрута уменьшилась с 3 до 2 переходов. | Появился один ложный сосед. Зафиксировано 246 повторных выпусков сообщений. |
| «Сивилла» | Честный сосед принял 3 или 10 фиктивных адресов, в зависимости от настроек. | Появились 3 фиктивных соседа и 3 записи топологии. |

Для сравнения устойчивости AODV и OLSR потребуются одинаковые топологии и серии запусков. Здесь топологии и моменты включения атак выбраны отдельно для проверки каждого механизма.

[Сводка AODV](patches/tests/results/aodv-validation-summary.json) · [Сводка OLSR](patches/tests/results/olsr-summary.json) · [Проверка комплекта](patches/tests/results/bundle-validation.json)

## Устройство реализации

- [AODV — чёрная и серая дыра](patches/aodv_implementation.md). Ложные ответы RREP, отбрасывание транзитных пакетов и счётчики.
- [AODV — туннель и «Сивилла»](patches/aodv_wormhole_sybil_notes.md). Скрытый переход, фиктивные адреса и проверки приёма.
- [OLSR — все четыре атаки](patches/olsr_implementation.md). Выбор MPR, ретрансляция, записи соседства и топологии.
- [Сценарии и скрипты проверки](patches/tests) · [Контрольные суммы](patches/manifest.json).

## Лицензия

Изменяемые файлы AODV и OLSR и сценарии C++ используют `GPL-2.0-only`. Исходные уведомления об авторстве и лицензиях сохраняются при применении патчей. См. [текст GPL v2](COPYING) и [исходники NS-3.49](https://gitlab.com/nsnam/ns-3-dev/-/tree/ns-3.49).
