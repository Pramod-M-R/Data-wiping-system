cmake_minimum_required(VERSION 3.16)
project(WipeEngine)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_AUTOMOC ON)
set(CMAKE_AUTOUIC ON)
set(CMAKE_AUTORCC ON)

set(CMAKE_PREFIX_PATH "C:/Qt/6.11.2/mingw_64")

find_package(Qt6 REQUIRED COMPONENTS Widgets)

add_executable(WipeEngine WIN32
    src/main.cpp
    src/MainWindow.cpp
    src/DeviceManager.cpp
    src/WipeEngine.cpp
    src/FileScanner.cpp
    src/Logger.cpp
    src/CertificateGenerator.cpp
    src/app.rc
    src/FileFingerprint.h
    src/FileFingerprint.cpp
    src/FeatureExtractor.h
    src/FeatureExtractor.cpp
    src/SimilarityCalculator.cpp
    src/SimilarityCalculator.h
    src/SimilarityEvaluator.cpp
    src/SimilarityEvaluator.h
    src/RecoverabilityEvaluator.cpp
    src/RecoverabilityEvaluator.h
)

target_link_libraries(WipeEngine PRIVATE Qt6::Widgets)