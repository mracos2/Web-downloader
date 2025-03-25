add_executable(${PROJECT_NAME}
    Web-Downloader.cpp
    Web-Downloader.h
)

target_include_directories(${PROJECT_NAME} PRIVATE
    ${Boost_INCLUDE_DIRS}
    ${OPENSSL_INCLUDE_DIR}
)

target_link_libraries(${PROJECT_NAME} PRIVATE
    ${Boost_LIBRARIES}
    OpenSSL::SSL
    Crypt32
    ws2_32
)