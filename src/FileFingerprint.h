#pragma once

struct FileFingerprint {
    double entropy = 0.0;
    double meanByteValue = 0.0;
    double standardDeviation = 0.0;
    double zeroBytePercentage = 0.0;
    double ffBytePercentage = 0.0;
    double uniqueByteRatio = 0.0;
    double chiSquare = 0.0;
    double printableBytePercentage = 0.0;
    double byteRange = 0.0;
    double dominantBytePercentage = 0.0;
};