Название:
    Проверка работы команды pwd из созданной директории


ID:
    PWD-2


Цель:
    Проверить работу команды pwd при создании новой директории, переходе в нее и вызова из нее данной команды.


Предусловия:
    Открытый терминал


Шаги:
    Шаг 1: Создать директории с помощью команды `mkdir -p ~/test1/test2/test3`
    Шаг 2: Перейти в созданную директорию командой `cd ~/test1/test2/test3`
    Шаг 3: Выполнить команду `pwd`


Ожидаемый результат:
    Вывод в терминал `/home/username/test1/test2/test3`


Постусловия:
    Удалить созданные директории командой `rm -r ~/test1`


Критерии прохождения:
    Вывод в терминал `/home/username/test1/test2/test3`


Критерии неуспешного завершения:
    Любое поведение, отличное от вывода в терминал `/home/username/test1/test2/test3`


Комментарии:
    -