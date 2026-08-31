#include "FeatureExtractor.h"

#include <QFile>
#include <array>
#include <cmath>

FileFingerprint FeatureExtractor::extractFeatures(const QString& filePath)
{
    FileFingerprint fingerprint;

    QFile file(filePath);

    if (!file.open(QIODevice::ReadOnly)) {
        return fingerprint;
    }

    // Stores how many times each byte value (0–255) occurs.
    std::array<unsigned long long, 256> frequency{};
    
    unsigned long long totalBytes = 0;
    unsigned long long zeroBytes = 0;
    unsigned long long ffBytes = 0;
    unsigned long long printableBytes = 0;

    double sum = 0.0;
    double sumSquares = 0.0;

    const qint64 chunkSize = 8192;

    while (!file.atEnd()) {

        QByteArray chunk = file.read(chunkSize);

        for (char character : chunk) {

            unsigned char byte =
                static_cast<unsigned char>(character);

            frequency[byte]++;
            totalBytes++;

            sum += byte;
            sumSquares += byte * byte;

            if (byte == 0x00)
                zeroBytes++;

            if (byte == 0xFF)
                ffBytes++;

            // Printable ASCII characters
            if (byte >= 32 && byte <= 126)
                printableBytes++;
        }
    }

    file.close();

    if (totalBytes == 0) {
        return fingerprint;
    }

    // -------------------------
    // 1. Mean byte value
    // -------------------------
    fingerprint.meanByteValue =
        sum / totalBytes;


    // -------------------------
    // 2. Standard deviation
    // -------------------------
    double variance =
        (sumSquares / totalBytes) -
        (fingerprint.meanByteValue *
         fingerprint.meanByteValue);

    fingerprint.standardDeviation =
        std::sqrt(std::max(0.0, variance));


    // -------------------------
    // 3. Zero-byte percentage
    // -------------------------
    fingerprint.zeroBytePercentage =
        (static_cast<double>(zeroBytes) / totalBytes) * 100.0;


    // -------------------------
    // 4. FF-byte percentage
    // -------------------------
    fingerprint.ffBytePercentage =
        (static_cast<double>(ffBytes) / totalBytes) * 100.0;


    // -------------------------
    // 5. Printable-byte percentage
    // -------------------------
    fingerprint.printableBytePercentage =
        (static_cast<double>(printableBytes) / totalBytes) * 100.0;


    // -------------------------
    // 6. Unique-byte ratio
    // -------------------------
    int uniqueBytes = 0;

    for (int i = 0; i < 256; i++) {
        if (frequency[i] > 0)
            uniqueBytes++;
    }

    fingerprint.uniqueByteRatio =
        (static_cast<double>(uniqueBytes) / 256.0) * 100.0;


    // -------------------------
    // 7. Dominant-byte percentage
    // -------------------------
    unsigned long long dominantFrequency = 0;

    for (int i = 0; i < 256; i++) {
        dominantFrequency =
            std::max(dominantFrequency, frequency[i]);
    }

    fingerprint.dominantBytePercentage =
        (static_cast<double>(dominantFrequency) /
         totalBytes) * 100.0;


    // -------------------------
    // 8. Byte range
    // -------------------------
    int minimumByte = 255;
    int maximumByte = 0;

    for (int i = 0; i < 256; i++) {

        if (frequency[i] > 0) {

            minimumByte =
                std::min(minimumByte, i);

            maximumByte =
                std::max(maximumByte, i);
        }
    }

    fingerprint.byteRange =
        maximumByte - minimumByte;


    // -------------------------
    // 9. Shannon entropy
    // -------------------------
    double entropy = 0.0;

    for (int i = 0; i < 256; i++) {

        if (frequency[i] > 0) {

            double probability =
                static_cast<double>(frequency[i]) /
                totalBytes;

            entropy -=
                probability *
                std::log2(probability);
        }
    }

    fingerprint.entropy = entropy;


    // -------------------------
    // 10. Chi-square statistic
    // -------------------------
    double expected =
        static_cast<double>(totalBytes) / 256.0;

    double chiSquare = 0.0;

    if (expected > 0) {

        for (int i = 0; i < 256; i++) {

            double difference =
                frequency[i] - expected;

            chiSquare +=
                (difference * difference) /
                expected;
        }
    }

    fingerprint.chiSquare = chiSquare;

    return fingerprint;
}