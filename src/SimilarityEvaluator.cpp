#include "SimilarityEvaluator.h"

#include <algorithm>
#include <cmath>
#include <vector>

double SimilarityEvaluator::calculateSimilarity(
    const FileFingerprint& before,
    const FileFingerprint& after)
{
    std::vector<double> beforeFeatures = {
        before.entropy,
        before.meanByteValue,
        before.standardDeviation,
        before.zeroBytePercentage,
        before.ffBytePercentage,
        before.printableBytePercentage,
        before.uniqueByteRatio,
        before.dominantBytePercentage,
        before.byteRange,
        before.chiSquare
    };

    std::vector<double> afterFeatures = {
        after.entropy,
        after.meanByteValue,
        after.standardDeviation,
        after.zeroBytePercentage,
        after.ffBytePercentage,
        after.printableBytePercentage,
        after.uniqueByteRatio,
        after.dominantBytePercentage,
        after.byteRange,
        after.chiSquare
    };

    double totalSimilarity = 0.0;

    for (size_t i = 0; i < beforeFeatures.size(); ++i) {

        double maxValue = std::max(
            std::abs(beforeFeatures[i]),
            std::abs(afterFeatures[i])
        );

        double similarity = 0.0;

        if (maxValue == 0.0) {
            similarity = 100.0;
        } else {
            double difference =
                std::abs(beforeFeatures[i] - afterFeatures[i]);

            similarity =
                std::max(0.0,
                    100.0 - (difference / maxValue) * 100.0
                );
        }

        totalSimilarity += similarity;
    }

    return totalSimilarity / beforeFeatures.size();
}
