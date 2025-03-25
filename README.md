# Web-Downloader

Консольная утилита для параллельной загрузки файлов по URL

## Зависимости
- Boost 1.66+ [ссылка](https://www.boost.org/)
- OpenSSL 1.1.1+ [ссылка](https://www.openssl.org/)
- C++17 компилятор

## Сборка
```bash
mkdir build
cd build
cmake ..
cmake --build .
```
## Использование

```bash
./web-downloader <url_file> <output_dir> <concurrency>
```
