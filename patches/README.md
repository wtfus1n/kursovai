# Запуск контрольных сценариев

[Главная страница проекта](../README.md)

## 1. Подготовьте рабочую копию

Из корня репозитория укажите пути к исходникам и новому каталогу. Значения `protocol` и `attack` выберите из таблицы ниже.

```bash
source_dir="$HOME/ns3-work/ns-3.49"
protocol=olsr
attack=sybil
work_dir="$HOME/ns3-work/check-${protocol}-${attack}"

python3 patches/prepare_variant.py "$source_dir" "$work_dir" \
  --protocol "$protocol" --attack "$attack"
```

Флаг `--check-only` выполняет сверку SHA-256 и пробное применение без создания рабочей копии. Для очередной атаки укажите новый каталог.

## 2. Настройте сборку

```bash
cd "$work_dir"
./ns3 configure --enable-modules=aodv,olsr,wifi,mobility,applications,point-to-point \
  --disable-python-bindings
```

Эта конфигурация включает модули для всех перечисленных сценариев. Для запуска штатных тестов протоколов добавьте `--enable-tests` на этапе конфигурации.

## 3. Соберите и запустите сценарий

Возьмите имя цели из таблицы. Например, для «Сивиллы» в OLSR:

```bash
./ns3 build olsr-sybil-check -j 4
./ns3 run 'olsr-sybil-check --enabled=0'
./ns3 run 'olsr-sybil-check --enabled=1'
```

Каждый набор аргументов в последнем столбце передаётся отдельным запуском `./ns3 run 'цель аргументы'`. Для серой дыры отдельно запустите сценарий с каждым значением вероятности.

| `--protocol` | `--attack` | Цель сборки | Аргументы сценария |
| --- | --- | --- | --- |
| `aodv` | `blackhole` | `aodv-drop-check` | `--malicious=0` и `--malicious=1` |
| `aodv` | `grayhole` | `aodv-drop-check` | `--malicious=1 --probability=0`, затем вероятности `0.5` и `1` |
| `aodv` | `wormhole` | `aodv-wormhole-check` | `--mode=0`, `--mode=1` и `--mode=2` |
| `aodv` | `sybil` | `aodv-sybil-check` | `--attack=0`, `--attack=1 --count=3` и `--attack=1 --count=10` |
| `olsr` | `blackhole` | `olsr-blackhole-check` | `--enabled=0` и `--enabled=1` |
| `olsr` | `grayhole` | `olsr-grayhole-check` | `--enabled=1 --probability=0`, затем вероятности `0.5` и `1` |
| `olsr` | `wormhole` | `olsr-wormhole-check` | `--enabled=0` и `--enabled=1` |
| `olsr` | `sybil` | `olsr-sybil-check` | `--enabled=0` и `--enabled=1` |

Результат выводится строкой JSON или строкой с префиксом `RESULT`. Описание полей и дополнительные режимы есть в документации по [AODV](aodv_implementation.md), [туннелю и «Сивилле» AODV](aodv_wormhole_sybil_notes.md) и [OLSR](olsr_implementation.md).

По умолчанию в проверках серой дыры отбрасывание действует с начала измеряемого потока. В AODV поток начинается на 2-й секунде, в OLSR — на 20-й, после обмена служебными сообщениями. При `p = 1` сценарии проверяют нулевую транзитную доставку.

## Серая дыра с отбрасыванием посреди потока

Параметр `--delayedStart=1` добавляет промежуток, в котором транзитные пакеты проходят через нарушителя. Команды ниже выполняются каждая в своей рабочей копии с соответствующим патчем.

```bash
# Копия с патчем серой дыры AODV
./ns3 run 'aodv-drop-check --malicious=1 --probability=1 --delayedStart=1'

# Копия с патчем серой дыры OLSR
./ns3 run 'olsr-grayhole-check --enabled=1 --probability=1 --delayedStart=1'
```

- **AODV.** Узел может отвечать на запросы маршрута с начала запуска. Вероятность отбрасывания равна нулю до 6-й секунды. В этот момент сценарий устанавливает заданное значение. Режим требует больше 100 пакетов в потоке.
- **OLSR.** Нарушитель участвует в обмене служебными сообщениями, а отбрасывание начинается на 30-й секунде по параметру `AttackStart`.

В выводе `receivedBefore` и `receivedAfter` означают число пакетов, полученных конечным узлом до и после момента начала отбрасывания. При `p = 1` оба сценария требуют нулевой доставки после переключения. [Результаты прогонов](tests/results/README.md#серая-дыра-с-задержкой)

<details>
<summary>Ручное применение патча</summary>

В корне отдельной копии NS-3.49 запустите следующие команды. Укажите абсолютный путь к каталогу `patches` клонированного репозитория.

```bash
patch_dir="$HOME/ns3-attacks/patches"
patch --dry-run --batch --forward --fuzz=0 -p1 < "$patch_dir/ns3-49-aodv-blackhole.patch"
patch --batch --forward --fuzz=0 -p1 < "$patch_dir/ns3-49-aodv-blackhole.patch"
cp "$patch_dir/tests/aodv-drop-check.cc" scratch/
```

</details>
## Общий сценарий сравнения

Файл [matched-attacks.cc](experiments/matched-attacks.cc) задаёт один стенд
для всех восьми вариантов. Для сравнения AODV и OLSR выберите одну атаку и
одинаковые значения параметров в обеих рабочих копиях.

- Параметр --nodes принимает значения от 25 до 256. По умолчанию
  --topology=grid строит решётку с двумя группами. Обычная связь проходит
  по верхнему ряду. Флаг --redundant=1 добавляет связь по последнему
  полному ряду.
- --topology=triangle соединяет три группы треугольником,
  --topology=ring соединяет четыре группы кольцом. В каждой группе
  узлы тоже образуют кольцо. При неделимом числе узлов размеры групп
  отличаются максимум на один.
- Четыре потока UDP идут между группами, четыре внутри. В каждом потоке
  80 пакетов по 128 байт с интервалом 250 мс. При одинаковых --seed и --run
  совпадают отправители, получатели и расписание.
- В Blackhole и Grayhole нарушитель расположен на стороне первой группы обычной
  связи с соседней группой. Он отбрасывает транзитные пакеты полностью или с
  вероятностью --probability соответственно. Флаг --controlPlaneAttack=1
  включает дополнительные действия протокола с маршрутными сообщениями
  для отдельного опыта.
- В Sybil один физический нарушитель отправляет --identities фиктивных
  HELLO с одинакового адресного диапазона, начиная с 1,5 с каждую секунду.
  В обоих протоколах подменяется IPv4-источник, а устройство отправителя
  остаётся тем же.
- В Wormhole два нарушителя находятся в среднем ряду решётки либо в серединах первых двух групп. Обычная
  межгрупповая связь сохраняется. Оба патча добавляют один и тот же
  канальный механизм пересылки, сохраняющий исходные адреса кадра.
  Параметр --tunnelDelayMs задаёт задержку в одну сторону. Обычная
  маршрутизация сама выбирает путь. Отдельно считаются кадры в туннеле и
  UDP-пакеты, доставленные после прохождения туннеля.

| Атака | Режимы --mode |
| --- | --- |
| Blackhole, Grayhole, Sybil | off, attack |
| Wormhole | off, control-only, control-and-data |

В обоих режимах атаки Wormhole туннель переносит сообщения маршрутизации и
ARP для разрешения адресов. В режиме control-and-data добавляется пересылка
пользовательских IPv4-пакетов. Канал моделирует задержку и окрестности
концов. Он не задаёт отдельную полосу пропускания или потери туннеля.

Подготовка и сборка двух копий для Wormhole. Команды выполняются в Linux
или WSL из корня проекта.

```bash
python3 patches/prepare_variant.py \
  "$HOME/ns3-work/ns-3.49" "$HOME/ns3-work/matched-aodv-wormhole" \
  --protocol aodv --attack wormhole --comparison
python3 patches/prepare_variant.py \
  "$HOME/ns3-work/ns-3.49" "$HOME/ns3-work/matched-olsr-wormhole" \
  --protocol olsr --attack wormhole --comparison
```

Внутри каждой копии сценарий собирается командой
`./ns3 build matched-attacks` после настройки сборки
`./ns3 configure --enable-modules=aodv,olsr,applications --disable-python-bindings`.
Одна и та же строка запуска для обоих протоколов имеет вид
`./ns3 run 'matched-attacks --nodes=100 --mode=control-only --run=1'`.
Для других атак меняются параметры подготовки рабочей копии и режимы
из таблицы выше.

Журналы и цифры из следующих разделов относятся к прежним проверкам.




Полная матрица содержит 5 040 симуляций. Для повторения из корня проекта
подготовьте отдельное дерево NS-3.49 и запустите сборщик результатов.

```bash
result_dir="$PWD/results/matched-5040"
bash patches/experiments/build-scale.sh "$result_dir"
python3 patches/experiments/run-matched.py "$(cat "$result_dir/build-dir.txt")" "$result_dir"
python3 patches/experiments/summarize-matched.py "$result_dir" "$result_dir/graphs"
```

Для графиков требуется Matplotlib. Скрипт сохраняет записи по потокам,
сводку по условиям и таблицу парных сравнений. При повторном запуске
готовые записи используются при совпадении контрольных сумм.


