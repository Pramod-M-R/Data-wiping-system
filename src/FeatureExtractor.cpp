#include "FeatureExtractor.h"

#include <QFile>

#include <array>
#include <cmath>


// =====================================================
// EXTRACT FEATURES FROM A FILE
// =====================================================

FileFingerprint FeatureExtractor::extractFeatures(
    const QString &filePath
)
{
    QFile file(filePath);

    if (!file.open(QIODevice::ReadOnly)) {
        return FileFingerprint{};
    }

    std::vector<uint8_t> data;

    while (!file.atEnd()) {

        QByteArray chunk =
            file.read(8192);

        for (char value : chunk) {

            data.push_back(
                static_cast<uint8_t>(
                    static_cast<unsigned char>(value)
                )
            );
        }
    }

    file.close();

    return extractFeaturesFromBytes(data);
}


// =====================================================
// EXTRACT FEATURES FROM RAW BYTES
// =====================================================

FileFingerprint FeatureExtractor::extractFeaturesFromBytes(
    const std::vector<uint8_t> &data
)
{
    FileFingerprint fingerprint{};


    if (data.empty()) {
        return fingerprint;
    }


    // -------------------------------------------------
    // BYTE HISTOGRAM
    // -------------------------------------------------

    std::array<unsigned long long, 256>
        byteCounts{};


    unsigned long long nullCount = 0;

    unsigned long long ffCount = 0;

    unsigned long long printableCount = 0;


    double byteSum = 0.0;

    double squareSum = 0.0;


    for (uint8_t value : data) {

        byteCounts[value]++;

        byteSum += value;

        squareSum +=
            static_cast<double>(value) *
            static_cast<double>(value);


        if (value == 0) {

            nullCount++;

        } else if (value == 0xFF) {

            ffCount++;
        }


        if (value >= 32 &&
            value <= 126) {

            printableCount++;
        }
    }


    const double totalBytes =
        static_cast<double>(data.size());


    // -------------------------------------------------
    // MEAN BYTE VALUE
    // -------------------------------------------------

    fingerprint.meanByteValue =
        byteSum / totalBytes;


    // -------------------------------------------------
    // STANDARD DEVIATION
    // -------------------------------------------------

    double variance =
        (squareSum / totalBytes)
        -
        (
            fingerprint.meanByteValue *
            fingerprint.meanByteValue
        );


    if (variance < 0.0) {

        variance = 0.0;
    }


    fingerprint.standardDeviation =
        std::sqrt(variance);


    // -------------------------------------------------
    // ZERO BYTE PERCENTAGE
    // -------------------------------------------------

    fingerprint.zeroBytePercentage =
        (
            static_cast<double>(nullCount)
            /
            totalBytes
        )
        * 100.0;


    // -------------------------------------------------
    // FF BYTE PERCENTAGE
    // -------------------------------------------------

    fingerprint.ffBytePercentage =
        (
            static_cast<double>(ffCount)
            /
            totalBytes
        )
        * 100.0;


    // -------------------------------------------------
    // PRINTABLE BYTE PERCENTAGE
    // -------------------------------------------------

    fingerprint.printableBytePercentage =
        (
            static_cast<double>(printableCount)
            /
            totalBytes
        )
        * 100.0;


    // -------------------------------------------------
    // UNIQUE VALUES + DOMINANT BYTE
    // -------------------------------------------------

    int uniqueValues = 0;

    unsigned long long maxCount = 0;

    int minValue = 255;

    int maxValue = 0;


    for (int i = 0; i < 256; i++) {

        if (byteCounts[i] > 0) {

            uniqueValues++;


            if (byteCounts[i] > maxCount) {

                maxCount =
                    byteCounts[i];
            }


            if (i < minValue) {

                minValue = i;
            }


            if (i > maxValue) {

                maxValue = i;
            }
        }
    }


    fingerprint.uniqueByteRatio =
        (
            static_cast<double>(uniqueValues)
            /
            256.0
        )
        * 100.0;


    fingerprint.dominantBytePercentage =
        (
            static_cast<double>(maxCount)
            /
            totalBytes
        )
        * 100.0;


    // -------------------------------------------------
    // BYTE RANGE
    // -------------------------------------------------

    fingerprint.byteRange =
        maxValue - minValue;


    // -------------------------------------------------
    // ENTROPY
    // -------------------------------------------------

    double entropy = 0.0;


    for (int i = 0; i < 256; i++) {

        if (byteCounts[i] == 0) {

            continue;
        }


        double probability =
            static_cast<double>(
                byteCounts[i]
            )
            /
            totalBytes;


        entropy -=
            probability *
            std::log2(probability);
    }


    fingerprint.entropy =
        entropy;


    // -------------------------------------------------
    // CHI-SQUARE
    // -------------------------------------------------

    double expectedCount =
        totalBytes / 256.0;


    double chiSquare = 0.0;


    if (expectedCount > 0.0) {

        for (int i = 0; i < 256; i++) {

            double difference =
                static_cast<double>(
                    byteCounts[i]
                )
                -
                expectedCount;


            chiSquare +=
                (
                    difference *
                    difference
                )
                /
                expectedCount;
        }
    }


    fingerprint.chiSquare =
        chiSquare;


    return fingerprint;
}