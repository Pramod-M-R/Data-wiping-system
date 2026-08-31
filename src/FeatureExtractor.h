#pragma once

#include <QString>
#include <vector>
#include <cstdint>

#include "FileFingerprint.h"


class FeatureExtractor
{
public:

    // Extract features from an existing file.
    FileFingerprint extractFeatures(
        const QString &filePath
    );

    // Extract features directly from raw bytes.
    // This will be useful later for deleted-file evaluation.
    FileFingerprint extractFeaturesFromBytes(
        const std::vector<uint8_t> &data
    );
};