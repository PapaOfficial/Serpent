# Serpent
Представлены 2 папки - Libakrypt 7 и Libakrypt 9, в них соответственно реализации шифра Serpent для 7 и 9 версии библиотеки Libakrypt 
(я изначально сделал для 7 версии, потом подредактировал под 9)

## Libakrypt 7
Здесь папка проекта Xcode (SerpentProject) и скриншот с результатами тестирования шифра Serpent, сама реализация шифра Serpent находится в serpent.h, а тестирование производится в main.c по аналогии с примером 11.5 test-internal-bckey02.c из документации библиотеки к 7 версии 

## Libakrypt 9
Здесь файл Serpent9.h в котором представлена реализация шифра Serpent для 9 версии библиотеки Libakrypt, а также скриншот ошибок при установке 9 версии библиотеки Libakrypt (9 версия у меня не поставилась, но serpent9.h должен на ней работать)

## Общее
Serpent.h и Serpent9.h писались по аналогии с реализацией шифра "Кузнечик" в Libakrypt

Функции, которые там определены:

ak_serpent_delete_keys - освобождение памяти, занимаемой развернутыми ключами алгоритма serpent

ak_serpent_schedule_keys - развертка ключей для алгоритма serpent

ak_serpent_encrypt - зашифрование одного блока информации шифром serpent

ak_serpent_decrypt - расшифрование одного блока информации шифра serpent

ak_bckey_context_create_serpent (ak_bckey_create_serpent) - инициализация контекста секретного ключа алгоритма блочного шифрования serpent



Официальное описание шифра - https://www.cl.cam.ac.uk/~rja14/Papers/ventura.pdf
