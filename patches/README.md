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

В сценарии серой дыры OLSR первые 20 секунд отведены на построение маршрутов. На 20-й секунде начинаются отбрасывание и измеряемый UDP-поток из 300 запланированных пакетов. При `p = 1` сценарий требует нулевую транзитную доставку.

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
