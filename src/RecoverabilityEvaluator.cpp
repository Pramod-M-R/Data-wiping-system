#include "RecoverabilityEvaluator.h"

#include <algorithm>
#include <cmath>


RecoverabilityResult RecoverabilityEvaluator::evaluate(
    const FileFingerprint &before,
    const FileFingerprint &after,
    double similarityScore
)
{
    RecoverabilityResult result;


    // Higher similarity means the data characteristics
    // are more similar to the original data.
    double recoverability =
        similarityScore;


    // If printable data remains after wiping,
    // increase the recoverability concern.

    if (
        after.printableBytePercentage >
        20.0
    )
    {
        recoverability += 10.0;
    }


    // If entropy remains very close to the
    // original data, increase concern.

    double entropyDifference =
        std::abs(
            before.entropy -
            after.entropy
        );


    if (entropyDifference < 0.5)
    {
        recoverability += 10.0;
    }


    result.recoverabilityPercentage =
        std::min(
            100.0,
            recoverability
        );


    result.riskLevel =
        determineRiskLevel(
            result.recoverabilityPercentage
        );


    result.recommendedMethod =
        recommendWipeMethod(
            result.recoverabilityPercentage
        );


    result.recommendation =
        getRecommendation(
            result.riskLevel,
            result.recommendedMethod
        );


    return result;
}


// =====================================================
// DETERMINE RISK LEVEL
// =====================================================

RiskLevel RecoverabilityEvaluator::determineRiskLevel(
    double recoverabilityPercentage
)
{
    if (recoverabilityPercentage <= 30.0)
    {
        return RiskLevel::LOW;
    }


    if (recoverabilityPercentage <= 60.0)
    {
        return RiskLevel::MEDIUM;
    }


    return RiskLevel::HIGH;
}


// =====================================================
// RECOMMEND WIPE METHOD
// =====================================================

WipeMethod RecoverabilityEvaluator::recommendWipeMethod(
    double recoverabilityPercentage
)
{
    if (recoverabilityPercentage <= 30.0)
    {
        return WipeMethod::ZEROS;
    }


    if (recoverabilityPercentage <= 60.0)
    {
        return WipeMethod::DOD_3PASS;
    }


    return WipeMethod::DOD_7PASS;
}


// =====================================================
// GENERATE RECOMMENDATION
// =====================================================

std::string RecoverabilityEvaluator::getRecommendation(
    RiskLevel riskLevel,
    WipeMethod method
)
{
    (void)method;


    if (riskLevel == RiskLevel::LOW)
    {
        return
            "Low recoverability risk. "
            "The wipe result appears effective.";
    }


    if (riskLevel == RiskLevel::MEDIUM)
    {
        return
            "Medium recoverability risk. "
            "A stronger multi-pass wipe is recommended.";
    }


    return
        "High recoverability risk. "
        "Use a stronger wipe method such as DoD 7-Pass.";
}