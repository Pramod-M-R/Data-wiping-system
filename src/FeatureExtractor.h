#pragma once

#include <QString>
#include "FileFingerprint.h"

class FeatureExtractor {
public:
    FileFingerprint extractFeatures(const QString& filePath);
};