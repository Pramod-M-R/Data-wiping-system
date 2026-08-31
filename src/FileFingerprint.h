#pragma once


struct FileFingerprint
{
    // Information / randomness of file data
    double entropy = 0.0;

    // Average byte value
    double meanByteValue = 0.0;

    // Distribution of byte values
    double standardDeviation = 0.0;

    // Percentage of zero bytes
    double zeroBytePercentage = 0.0;

    // Percentage of 0xFF bytes
    double ffBytePercentage = 0.0;

    // Percentage of printable ASCII bytes
    double printableBytePercentage = 0.0;

    // Number of unique byte values used
    double uniqueByteRatio = 0.0;

    // Most common byte percentage
    double dominantBytePercentage = 0.0;

    // Difference between maximum and minimum byte
    double byteRange = 0.0;

    // Statistical distribution measurement
    double chiSquare = 0.0;
};