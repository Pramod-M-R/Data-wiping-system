#pragma once

#include <string>

#include "FileFingerprint.h"
#include "WipeEngine.h"


enum class RiskLevel
{
    LOW,
    MEDIUM,
    HIGH
};


struct RecoverabilityResult
{
    double recoverabilityPercentage = 0.0;

    RiskLevel riskLevel = RiskLevel::LOW;

    WipeMethod recommendedMethod =
        WipeMethod::ZEROS;

    std::string recommendation;
};


class RecoverabilityEvaluator
{
public:

    RecoverabilityResult evaluate(
        const FileFingerprint &before,
        const FileFingerprint &after,
        double similarityScore
    );


private:

    RiskLevel determineRiskLevel(
        double recoverabilityPercentage
    );


    WipeMethod recommendWipeMethod(
        double recoverabilityPercentage
    );


    std::string getRecommendation(
        RiskLevel riskLevel,
        WipeMethod method
    );
};