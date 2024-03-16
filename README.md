# Лабораторные работы

## Лабораторная работа №1.

Загрузка ядра и запуск.
Пользовательской точкой входа в загрузчик является функция UefiMain в файле Bootloader.c. Её имя, как и файл, в котором она находится, определяется в манифесте сборки загрузчика — Loader.inf. В манифесте также указываются используемые в загрузчике библиотеки. Служебные библиотеки точки входа, например, UefiApplicationEntryPoint, осуществляют проверку совместимости платформы в момент запуска загрузчика, проводят инициализацию других библиотек через их конструкторы и передают управление в пользовательскую точку входа. В случае завершения работы приложения данная библиотека также вызывает деструкторы используемых библиотек. Вместо стандартной библиотеки языка C в EDK II используются собственные библиотечные функции и сервисы. О возможностях UEFI Boot Services (gBS) и UEFI Runtime Services (gRT) можно прочесть в спецификации UEFI. О возможностях используемых библиотек можно узнать в соответствующих заголовочных файлах пакета, интерфейс которого конкретная библиотека реализует. Например, интерфейс библиотеки отладки, который предоставляет средства вывода отладочных сообщений и встроенные проверки (assertions), описан в LoaderPkg/UDK/MdePkg/Include/Library/DebugLib.h.

(как именно эта функция инитит все конструкторы ? где этот вызов ? как происходят переключение фаз загрузчика * )

Основная цель данной лр была в том, чтобы поуправлять графикой (разрешением экрана, например) через gST, в частности через gBS (см. функцию InitGraphics в Bootloader.c) и загрузить ядро с диска, после чего передать ему управление ядру.

## Лабораторная работа №2.

Работа в различных режимах процессора.

Защищённый режим (Protected mode) процессора является основным режимом для 32-битных процессоров Intel, появившийся в Intel 80286. Данный режим использует 32-битный набор команд, позволяет адресовать больше памяти (32-битная адресация без PAE) и поддержку виртуальной памяти, позволяющую реализовывать изоляцию задач в операционной системе.

Длинный режим (Long mode, IA-32e mode) является основным режимом работы для 64-битных процессоров Intel. Данный режим использует 64-битный набор команд и использует 64-битную (или 48-битную в ранних версиях) адресацию памяти. В числе ключевых отличий от защищённого режима является обязательное использование виртуальной памяти, отказ от сегментной адресации и упрощённая относительная адресация для поддержки PIC/PIE кода.

Нужно было сделать переключение из x32 в x64 мод (LoaderPkg/Loader/Ia32/Transition.nasm). А также раскрутить стек вызовов, чтобы можно было понять, где программа крашается (см. kern/monitor.c).

(для чего нужно такое переключение, почему нельзя сразу в одном mode всё делать?)

## Лабораторная работа №3.

Одним из основных ресурсов компьютера является центральный процессор. Для эффективного использования процессора операционная система должна управлять задачами, которые выполняются на нем. Современные компьютеры, как правило, должны выполнять несколько задач одновременно. В случае с персональным компьютером помимо той программы, с которой в данный момент осуществляется взаимодействие, могут выполняться программы обмена сообщениями, музыкальные проигрыватели, программы синхронизации с облачным хранилищем и т. д. Веб-сервер может обрабатывать сразу несколько запросов, часть из которых может ожидать обмена данными с диском. Даже вычислительные программы для более полного использования современных многоядерных процессоров рекомендуется по возможности разделять на несколько одновременно выполняющихся вычислений.

Основная цель данной лабораторной работы:
* создать сущность процессов
* научиться связывать эльф-файлы с процессами
* запустить процессы исполнять эльфы
* написать Round-Robin планировщик

Пока что здесь ещё нет виртуальной памяти. Все процессы мапятся сразу на физическую и имеют доступ друг к другу

# Другое

This branch contains vastly improved kernel memory
subsystem with following new features:
    * 2M/1G pages
    * Lazy copying/lazy memory allocation
        * Used for speeding up ASAN memory allocation
        * Kernel memory is also lazily allocated
    * NX flag
    * Buddy physical memory allocator
    * O((log N)^2) region manipulation
    * More convenient syscall API
    * IPC with memory regions of size larger than 4K
        * Not used at the moment but would be useful
          for file server optimization
    * Reduced memory consumption by a lot
    * All supported sanitizers can work simultaneously
      with any amount of memory (as long as bootloader can allocate enough memory for the kernel)

The code is mostly located in kern/pmap.c
A set of trees is used for holding metadata (nodes are of type struct Page):
    * A tree describing physical memory
    * One tree for every address space (for every environment and kernel)

TODO
    * Replace user_mem_assert with exception-based code
        * copyin/copyout functions
    * Refactor address space and move all kernel-only memory
      regions to canonical upper part of address space
      (this requires copyin/copyout functions because
       ASAN should never touch user-space memory)
