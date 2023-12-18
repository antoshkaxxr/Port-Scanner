# Port-Scanner
_Рекомендуется запускать утилиту на Linux в связи с порой неожиданными особенностями работы модуля scapy на Windows._

Склонируйте репозиторий.
Для запуска утилиты установите необходимые зависимости:
```pip install scapy```
Запуск утилиты из командной строки:
```sudo python3 portscan.py --timeout 2 --num-threads 8 -v -g 1.1.1.1 tcp/70-85,90 udp/53,200-205```
где --timeout, --num-threads, -v (verbose mode) и -g (guess protocol) опциональны.

## Особенности реализации
Основные функции сканера расположены в ```scanner.py```.
- **UDP-сканирование** (функция ```scan_udp```)
- **TCP-сканирование с формированием пакетов с использованием модуля ```scapy```** (функция ```scan_tcp```)
- **Распараллеливание через многопоточность**. Причём намеренно используется семафор ```thread_semaphore```, который контролирует количество одновременно выполняющихся потоков в функциях ```scan_tcp``` и ```scan_udp``` во избежание единовременного создания большого числа открытых сокетов
- **Подробный режим** реализован с помощью модуля ```time```
- **Определение протоколов** (```HTTP```, ```DNS```, ```ECHO```) - см. файл ```protocol_definition.py```

## Дополнительные требования
- Параметры запуска обрабатываются в точности так, как описано в условии задания:
```[OPTIONS] IP_ADDRESS [{tcp|udp}[/[PORT|PORT-PORT],...]]...```
Кроме того, добавлены проверки валидации, обрабатывающие случаи неверно указанных соединения (не tcp и не udp), диапазона портов (неожиданные символы, кроме цифр 0-9 и знака дефис)
- Нет оставленных полуоткрытых соединений
- Вывод происходит строго в соответствии с тем форматом, который требуется:
```TCP|UDP PORT [TIME,ms] [PROTOCOL|-]```
