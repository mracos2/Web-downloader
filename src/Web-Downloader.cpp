#include <iostream>
#include <fstream>
#include <vector>
#include <queue>
#include <thread>
#include <mutex>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <random>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/version.hpp>
#include <boost/asio/connect.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/asio/ssl.hpp>
#include <regex>
#include <openssl/ssl.h>

namespace beast = boost::beast;
namespace http = beast::http;
namespace net = boost::asio;
namespace ssl = net::ssl;
using tcp = net::ip::tcp;
namespace fs = std::filesystem;

// Генерация уникального имени файла
std::string generate_unique_name() {
    auto now = std::chrono::system_clock::now();
    auto time_ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
        now.time_since_epoch()
    ).count();

    static std::random_device rd;
    static std::mt19937_64 gen(rd());
    std::uniform_int_distribution<uint64_t> dis;
    uint64_t rand_val = dis(gen);

    std::stringstream ss;
    ss << std::hex << time_ns << "_" << rand_val;
    return ss.str();
}

// RAII для временных файлов
class TempFileGuard {
    fs::path path_;
public:
    explicit TempFileGuard(const fs::path& path) : path_(path) {}
    ~TempFileGuard() {
        if (!path_.empty()) {
            std::error_code ec;
            fs::remove(path_, ec);
        }
    }
    void release() { path_.clear(); }
};

// Логирование с временем
std::string current_time() {
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()) % 1000;
    auto timer = std::chrono::system_clock::to_time_t(now);

    std::tm bt;
#if defined(_WIN32)
    localtime_s(&bt, &timer);
#else
    localtime_r(&timer, &bt);
#endif

    std::ostringstream oss;
    oss << std::put_time(&bt, "%Y-%m-%d %H:%M:%S");
    oss << '.' << std::setfill('0') << std::setw(3) << ms.count();
    return oss.str();
}

// Обработка имени файла
std::string sanitize_filename(std::string filename) {
    if (filename.length() > 255) {
        filename = filename.substr(0, 255);
    }
    for (auto& c : filename) {
        if (!((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '.' || c == '-' || c == '_')) {
            c = '_';
        }
    }
    return filename;
}

std::string decode_rfc5987(const std::string& s) {
    std::string res;
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] == '%' && i + 2 < s.size()) {
            int val;
            std::istringstream iss(s.substr(i + 1, 2));
            if (iss >> std::hex >> val) {
                res += static_cast<char>(val);
                i += 2;
            }
            else {
                res += s[i];
            }
        }
        else {
            res += s[i];
        }
    }
    return res;
}

std::string get_filename(const http::response<http::file_body>& res, const std::string& url) {
    auto disposition = res.find(http::field::content_disposition);
    if (disposition != res.end()) {
        std::string value(disposition->value().data(), disposition->value().size());

        // Поиск RFC 5987 (регистронезависимый)
        size_t pos_utf8 = value.find("filename*=utf-8''");
        if (pos_utf8 == std::string::npos) {
            pos_utf8 = value.find("filename*=UTF-8''");
        }
        if (pos_utf8 != std::string::npos) {
            std::string encoded_name = value.substr(pos_utf8 + 17);
            std::string decoded_name = decode_rfc5987(encoded_name);
            return sanitize_filename(decoded_name);
        }

        size_t pos = value.find("filename=");
        if (pos != std::string::npos) {
            std::string filename = value.substr(pos + 9);
            if (filename.front() == '"' || filename.front() == '\'') {
                size_t end = filename.find(filename.front(), 1);
                if (end != std::string::npos) {
                    filename = filename.substr(1, end - 1);
                }
            }
            else {
                size_t end = filename.find(';');
                if (end != std::string::npos) {
                    filename = filename.substr(0, end);
                }
            }
            return sanitize_filename(filename);
        }
    }

    // Обработка URL
    size_t question_mark = url.find('?');
    std::string clean_url = url.substr(0, question_mark);
    size_t last_slash = clean_url.find_last_of('/');
    std::string filename_part = (last_slash != std::string::npos)
        ? clean_url.substr(last_slash + 1)
        : "file";

    size_t hash = filename_part.find('#');
    if (hash != std::string::npos) {
        filename_part = filename_part.substr(0, hash);
    }

    return sanitize_filename(filename_part);
}

fs::path construct_unique_path(const fs::path& dir, const std::string& filename) {
    std::string base_name = filename;
    std::string ext;

    size_t dot_pos = filename.find_last_of('.');
    if (dot_pos != std::string::npos) {
        base_name = filename.substr(0, dot_pos);
        ext = filename.substr(dot_pos);
    }

    int counter = 0;
    fs::path dest;
    do {
        std::string suffix = (counter == 0) ? "" : " (" + std::to_string(counter) + ")";
        dest = dir / (base_name + suffix + ext);
        counter++;
    } while (fs::exists(dest));

    return dest;
}

void download_url(const std::string& url, const fs::path& output_dir) {
    std::cout << "[" << current_time() << "] Starting download: " << url << std::endl;

    try {
        // Парсинг URL
        size_t pos_protocol = url.find("://");
        if (pos_protocol == std::string::npos) throw std::runtime_error("Invalid URL");
        std::string protocol = url.substr(0, pos_protocol);
        std::string host_port_path = url.substr(pos_protocol + 3);

        size_t path_pos = host_port_path.find('/');
        std::string host_port = host_port_path.substr(0, path_pos);
        std::string target = (path_pos != std::string::npos) ? host_port_path.substr(path_pos) : "/";

        size_t colon_pos = host_port.find(':');
        std::string host = host_port.substr(0, colon_pos);
        std::string port = (colon_pos != std::string::npos) ? host_port.substr(colon_pos + 1) : (protocol == "https" ? "443" : "80");

        // Подготовка SSL
        net::io_context ioc;
        ssl::context ctx(ssl::context::tls_client);
        ctx.set_verify_mode(ssl::verify_none);
        ctx.set_default_verify_paths();

        // Настройка TLS
        SSL_CTX_set_options(ctx.native_handle(),
            SSL_OP_ALL | SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 |
            SSL_OP_NO_TLSv1 | SSL_OP_NO_TLSv1_1);

        ssl::stream<beast::tcp_stream> stream(ioc, ctx);
        tcp::resolver resolver(ioc);

        // Подключение
        auto const results = resolver.resolve(host, port);
        beast::get_lowest_layer(stream).connect(results);
        stream.handshake(ssl::stream_base::client);

        // Отправка запроса
        http::request<http::empty_body> req{ http::verb::get, target, 11 };
        req.set(http::field::host, host);
        req.set(http::field::user_agent, BOOST_BEAST_VERSION_STRING);
        http::write(stream, req);

        // Получение ответа
        beast::flat_buffer buffer;
        http::response_parser<http::file_body> parser;
        parser.body_limit((std::numeric_limits<uint64_t>::max)());

        // Временный файл
        fs::path temp_path = fs::temp_directory_path() / generate_unique_name();
        beast::error_code ec;
        http::file_body::value_type file;
        file.open(temp_path.string().c_str(), beast::file_mode::write, ec);
        if (ec) throw std::runtime_error("Failed to create temp file");

        TempFileGuard temp_guard(temp_path);
        parser.get().body() = std::move(file);
        http::read(stream, buffer, parser);

        // Проверка статуса
        if (parser.get().result() != http::status::ok) {
            std::cout << "[" << current_time() << "] Error: " << url << " - HTTP " << parser.get().result_int() << std::endl;
            return;
        }

        // Сохранение файла
        std::string filename = get_filename(parser.get(), url);
        fs::path dest_path = construct_unique_path(output_dir, filename);
        parser.get().body().close();

        fs::rename(temp_path, dest_path);
        temp_guard.release();
        std::cout << "[" << current_time() << "] Downloaded: " << url << " -> " << dest_path << std::endl;
    }
    catch (const std::exception& e) {
        std::cout << "[" << current_time() << "] Error: " << url << " - " << e.what() << std::endl;
    }
}

int main(int argc, char* argv[]) {
    if (argc != 4) {
        std::cerr << "Usage: " << argv[0] << " <url_file> <output_dir> <concurrency>\n";
        return 1;
    }

    std::cout << "[" << current_time() << "] Program started\n";
    std::cout << "[" << current_time() << "] Params: " << argv[1] << " " << argv[2] << " " << argv[3] << "\n";

    fs::path url_file(argv[1]), output_dir(argv[2]);
    int concurrency = std::stoi(argv[3]);
    if (concurrency < 1 || concurrency > 999) {
        std::cerr << "Error: Concurrency must be between 1 and 999.\n";
        return 1;
    }

    // Чтение URL
    std::vector<std::string> urls;
    std::ifstream file(url_file);
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            urls.push_back(line);
        }
    }

    // Создание директории
    fs::create_directories(output_dir);

    // Запуск потоков
    std::queue<std::string> url_queue;
    std::mutex queue_mutex;
    for (const auto& url : urls) {
        url_queue.push(url);
    }

    auto worker = [&] {
        while (true) {
            std::string url;
            {
                std::lock_guard<std::mutex> lock(queue_mutex);
                if (url_queue.empty()) {
                    return;
                }
                url = url_queue.front();
                url_queue.pop();
            }
            download_url(url, output_dir);
        }
        };

    std::vector<std::thread> threads;
    threads.reserve(concurrency);
    for (int i = 0; i < concurrency; ++i) {
        threads.emplace_back(worker);
    }
    for (auto& t : threads) {
        t.join();
    }

    std::cout << "[" << current_time() << "] Program finished\n";
    return 0;
}

