# CryptoPro-python

Интерфейс к библиотеке CSP из python.

## Установка

Для компиляции необходим [swig](http://www.swig.org) версии не ниже 2.0.7 и
[fabric](https://pypi.python.org/pypi/Fabric). На системе должен быть
установлены пакеты, необходимые для сборки расширений Python и SDK КриптоПро.
Для работы тестов нужна полная установка КриптоПро и пакет [nose](https://pypi.python.org/pypi/nose).

Сборка пакета для версии Python, используемой по умолчанию:
```
fab rebuild
```

Можно указать версию интерпретатора, отличную от дефолтной:
```
fab rebuild:3.3
```

Тестирование:

```
fab test
```

или

```
fab test:3.3
```

Сборка на удаленной машине (параметры см. в `fabfile.py`):
```
fab deploy
```

## Документация

В начальной стадии документация ведется в
[wiki](https://bitbucket.org/andviro/cpro-py/wiki), также функциональность
задокументирована вместе с тестами в `tests/test\_csp.py`.