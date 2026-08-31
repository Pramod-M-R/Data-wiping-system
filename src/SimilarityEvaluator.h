#pragma once

#include "FileFingerprint.h"

class SimilarityEvaluator
{
public:
    double calculateSimilarity(
        const FileFingerprint& before,
        const FileFingerprint& after
    );
};