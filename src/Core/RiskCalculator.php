<?php

class RiskCalculator
{
    private array $assetValues = [
        "user_data" => 100000,
        "payment_data" => 500000,
        "health_data" => 1000000,
        "trade_secrets" => 5000000,
    ];

    public function calculateBusinessRisk(
        array $vulnerability,
        array $context,
    ): float {
        $likelihood = $this->calculateLikelihood($vulnerability);
        $impact = $this->calculateBusinessImpact($vulnerability, $context);

        $risk = $likelihood * $impact;

        return round($risk, 2);
    }

    private function calculateLikelihood(array $vulnerability): float
    {
        $likelihood = 0.5;

        if ($vulnerability["attack_vector"] === "NETWORK") {
            $likelihood *= 1.5;
        }

        if ($vulnerability["attack_complexity"] === "LOW") {
            $likelihood *= 1.3;
        }

        if ($vulnerability["exploit_available"] ?? false) {
            $likelihood *= 1.4;
        }

        if ($vulnerability["publicly_disclosed"] ?? false) {
            $likelihood *= 1.3;
        }

        return min($likelihood, 1.0);
    }

    private function calculateBusinessImpact(
        array $vulnerability,
        array $context,
    ): float {
        $impact = 0;

        if ($vulnerability["data_exposure_risk"] === "HIGH") {
            $dataType = $context["data_type"] ?? "user_data";
            $recordCount = $context["affected_records"] ?? 1000;
            $impact +=
                ($this->assetValues[$dataType] ?? 10000) *
                ($recordCount / 1000);
        }

        if ($vulnerability["affects_availability"]) {
            $revenuePerHour = $context["revenue_per_hour"] ?? 10000;
            $expectedDowntime = $this->estimateDowntime($vulnerability);
            $impact += $revenuePerHour * $expectedDowntime;
        }

        if ($vulnerability["severity"] === "CRITICAL") {
            $impact += $context["brand_value"] ?? 500000 * 0.1; // 10% brand impact
        }

        if (!empty($vulnerability["compliance_impact"])) {
            foreach ($vulnerability["compliance_impact"] as $standard) {
                $impact += $this->getCompliancePenalty($standard);
            }
        }

        $impact += $this->estimateRemediationCost($vulnerability);

        return $impact;
    }

    public function estimateLoss(array $vulnerability): array
    {
        $baseImpact = $vulnerability["base_score"] * 100000;

        return [
            "minimum" => $baseImpact * 0.5,
            "expected" => $baseImpact,
            "maximum" => $baseImpact * 3,
            "currency" => "USD",
            "confidence" => $this->getConfidenceLevel($vulnerability),
        ];
    }

    private function estimateDowntime(array $vulnerability): float
    {
        $severityHours = [
            "CRITICAL" => 24,
            "HIGH" => 8,
            "MEDIUM" => 4,
            "LOW" => 1,
        ];

        return $severityHours[$vulnerability["severity"]] ?? 1;
    }

    private function getCompliancePenalty(string $standard): float
    {
        $penalties = [
            "PCI-DSS" => 500000,
            "GDPR" => 1000000,
            "HIPAA" => 1500000,
            "SOC2" => 250000,
        ];

        return $penalties[$standard] ?? 100000;
    }

    private function estimateRemediationCost(array $vulnerability): float
    {
        $hourlyRate = 150;

        $effortHours = [
            "CRITICAL" => 40,
            "HIGH" => 24,
            "MEDIUM" => 16,
            "LOW" => 8,
        ];

        $hours = $effortHours[$vulnerability["severity"]] ?? 8;
        return $hours * $hourlyRate;
    }

    private function getConfidenceLevel(array $vulnerability): string
    {
        if (
            $vulnerability["exploit_available"] &&
            $vulnerability["cvss_vector"]
        ) {
            return "HIGH";
        }
        if ($vulnerability["base_score"] > 7.0) {
            return "MEDIUM";
        }
        return "LOW";
    }

    public function calculateExposureTime(array $vulnerability): int
    {
        $patchingDays = [
            "CRITICAL" => 1,
            "HIGH" => 7,
            "MEDIUM" => 30,
            "LOW" => 90,
        ];

        return $patchingDays[$vulnerability["severity"]] ?? 90;
    }

    public function getRiskMatrix(float $likelihood, float $impact): array
    {
        if ($likelihood >= 0.7 && $impact >= 500000) {
            $level = "EXTREME";
            $action = "IMMEDIATE ACTION REQUIRED";
        } elseif ($likelihood >= 0.5 && $impact >= 250000) {
            $level = "HIGH";
            $action = "Urgent remediation needed";
        } elseif ($likelihood >= 0.3 || $impact >= 100000) {
            $level = "MEDIUM";
            $action = "Schedule remediation";
        } else {
            $level = "LOW";
            $action = "Monitor and review";
        }

        return [
            "risk_level" => $level,
            "recommended_action" => $action,
            "likelihood_percent" => round($likelihood * 100, 1),
            "impact_usd" => $impact,
        ];
    }
}
