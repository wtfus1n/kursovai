# AODV и OLSR в NS-3.49

Учебный проект по сравнению маршрутизации AODV и OLSR в самоорганизующихся сетях. Для каждого протокола есть штатный сценарий и четыре модели нарушений.

## Структура репозитория

| Путь | Содержимое |
| --- | --- |
| [patches/aodv/](patches/aodv/) | Пять патчей AODV |
| [patches/olsr/](patches/olsr/) | Пять патчей OLSR |
| [simulation/checks/](simulation/checks/) | Отдельные сценарии проверки |
| [simulation/comparison/](simulation/comparison/) | Исходный код сравнительного сценария |
| [run.sh](run.sh) | Запуск эталонного сценария AODV или OLSR |

## Что входит в набор

| Вариант | Что моделирует |
| --- | --- |
| Эталон | Доставку пакетов при штатной маршрутизации |
| Чёрная дыра | Полную потерю транзитных пакетов, попавших под воздействие |
| Серая дыра | Выборочную потерю транзитных пакетов |
| Туннель | Искажение представления о связности удалённых участков |
| Сивилла | Появление нескольких сетевых идентификаторов у одного узла |

Патч определяет поведение узла. Сценарий моделирования задаёт число узлов, их размещение, связность и трафик. Эталонные патчи добавляют по одному сценарию в `scratch/` штатного NS‑3.49.

## Запуск эталонов

В примере `~/kursovai` и `~/ns-3.49` — локальные копии репозитория и [NS‑3.49](https://gitlab.com/nsnam/ns-3-dev/-/tree/ns-3.49).

~~~bash
cd ~/ns-3.49
patch -p1 < ~/kursovai/patches/aodv/ns3-49-aodv-baseline.patch
patch -p1 < ~/kursovai/patches/olsr/ns3-49-olsr-baseline.patch
./ns3 configure --enable-modules=aodv,olsr,wifi,mobility,applications --disable-python-bindings
bash ~/kursovai/run.sh "$PWD" aodv
bash ~/kursovai/run.sh "$PWD" olsr
~~~

Оба эталона по умолчанию передают 20 UDP-датаграмм между крайними узлами линии из трёх устройств, начиная с 20-й секунды. Для сравнения при других условиях передай обоим запускам одинаковые параметры, например `--nodes=5 --packets=12 --start=25`. В выводе `sent` — число отправленных датаграмм, `received` — число принятых, `pdr_percent` — процент доставки.

## Архив

- [Журналы 5 040 прогонов, отчёт и презентация](https://github.com/wtfus1n/kursovai/tree/oldmian/results/matched-5040).
- [Журналы коротких проверок](https://github.com/wtfus1n/kursovai/tree/oldmian/patches/tests/results).
- [Прежняя структура, технические описания и служебные скрипты](https://github.com/wtfus1n/kursovai/tree/75030558d9796e39704c35d19022ae1ed1fa4dc9/patches).

## Лицензия

Изменяемые файлы AODV и OLSR и сценарии C++ используют GPL-2.0-only. См. [текст лицензии](COPYING).
