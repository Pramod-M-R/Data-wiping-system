#include "RecoverabilityEvaluator.h"

#include <algorithm>

RecoverabilityResult RecoverabilityEvaluator::evaluate(
    const FileFingerprint& before,
    const FileFingerprint& after,
    double similarityScore)
{
    RecoverabilityResult result;

    // Baseline recoverability comes from similarity.
    // Higher similarity means more characteristics of the
    // original data may still remain.
    double recoverability = similarityScore;

    // Increase concern if significant printable data remains.
    if (after.printableBytePercentage > 20.0) {
        recoverability += 10.0;
    }

    // Increase concern if the after-wipe entropy remains
    // relatively close to the original entropy.
    double entropyDifference =
        std::abs(before.entropy - after.entropy);

    if (entropyDifference < 0.5) {
        recoverability += 10.0;
    }

    result.recoverabilityPercentage =
        std::min(100.0, recoverability);

    result.riskLevel =
        determineRiskLevel(result.recoverabilityPercentage);

    result.recommendedMethod =
        recommendWipeMethod(result.recoverabilityPercentage);

    result.recommendation =
        getRecommendation(
            result.riskLevel,
            result.recommendedMethod
        );

    return result;
}


RiskLevel RecoverabilityEvaluator::determineRiskLevel(
    double recoverabilityPercentage)
{
    if (recoverabilityPercentage <= 30.0) {
        return RiskLevel::LOW;
    }

    if (recoverabilityPercentage <= 60.0) {
        return RiskLevel::MEDIUM;
    }

    return RiskLevel::HIGH;
}


WipeMethod RecoverabilityEvaluator::recommendWipeMethod(
    double recoverabilityPercentage)
{
    if (recoverabilityPercentage <= 30.0) {
        return WipeMethod::ZEROS;
    }

    if (recoverabilityPercentage <= 60.0) {
        return WipeMethod::DOD_3PASS;
    }

    return WipeMethod::DOD_7PASS;
}


std::string RecoverabilityEvaluator::getRecommendation(
    RiskLevel riskLevel,
    WipeMethod method)
{
    if (riskLevel == RiskLevel::LOW) {
        return "Low recoverability risk. Current wipe result appears effective.";
    }

    if (riskLevel == RiskLevel::MEDIUM) {
        return "Medium recoverability risk. A stronger multi-pass wipe is recommended.";
    }

    return "High recoverability risk. Use a stronger wipe method such as DoD 7-Pass.";
}
