<?php

namespace SecurityAnalyzer\Core;
class SeverityScorer
{
    const CRITICAL = "CRITICAL";
    const HIGH = "HIGH";
    const MEDIUM = "MEDIUM";
    const LOW = "LOW";
    const INFO = "INFO";

    const AV_NETWORK = 0.85;
    const AV_ADJACENT = 0.62;
    const AV_LOCAL = 0.55;
    const AV_PHYSICAL = 0.2;

    const AC_LOW = 0.77;
    const AC_HIGH = 0.44;

    const PR_NONE = 0.85;
    const PR_LOW = 0.62;
    const PR_HIGH = 0.27;

    const UI_NONE = 0.85;
    const UI_REQUIRED = 0.62;

    const SCOPE_UNCHANGED = "U";
    const SCOPE_CHANGED = "C";

    const IMPACT_HIGH = 0.56;
    const IMPACT_LOW = 0.22;
    const IMPACT_NONE = 0.0;

    /**
     *
     *
     * @param array $metrics
     * @return float
     */
    public function calculateBaseScore(array $metrics): float
    {
        $av = $metrics["attack_vector"] ?? self::AV_NETWORK;
        $ac = $metrics["attack_complexity"] ?? self::AC_LOW;
        $pr = $metrics["privileges_required"] ?? self::PR_NONE;
        $ui = $metrics["user_interaction"] ?? self::UI_NONE;
        $scope = $metrics["scope"] ?? self::SCOPE_UNCHANGED;
        $c = $metrics["confidentiality_impact"] ?? self::IMPACT_HIGH;
        $i = $metrics["integrity_impact"] ?? self::IMPACT_HIGH;
        $a = $metrics["availability_impact"] ?? self::IMPACT_HIGH;

        if ($scope === self::SCOPE_CHANGED) {
            if ($pr === self::PR_LOW) {
                $pr = 0.68;
            }
            if ($pr === self::PR_HIGH) {
                $pr = 0.5;
            }
        }

        $iss = 1 - (1 - $c) * (1 - $i) * (1 - $a);

        if ($scope === self::SCOPE_UNCHANGED) {
            $impact = 6.42 * $iss;
        } else {
            $impact = 7.52 * ($iss - 0.029) - 3.25 * pow($iss - 0.02, 15);
        }

        if ($impact <= 0) {
            return 0.0;
        }

        $exploitability = 8.22 * $av * $ac * $pr * $ui;

        if ($scope === self::SCOPE_UNCHANGED) {
            $baseScore = min($impact + $exploitability, 10);
        } else {
            $baseScore = min(1.08 * ($impact + $exploitability), 10);
        }

        return round($baseScore, 1);
    }

    /**
     *
     *
     * @param float $baseScore
     * @param array $temporal
     * @return float
     */
    public function calculateTemporalScore(
        float $baseScore,
        array $temporal,
    ): float {
        $exploitMaturity = $temporal["exploit_maturity"] ?? 1.0;
        $remediationLevel = $temporal["remediation_level"] ?? 1.0;
        $reportConfidence = $temporal["report_confidence"] ?? 1.0;

        $temporalScore =
            $baseScore *
            $exploitMaturity *
            $remediationLevel *
            $reportConfidence;

        return round($temporalScore, 1);
    }

    /**
     *
     *
     * @param float $baseScore
     * @param array $environmental
     * @return float
     */
    public function calculateEnvironmentalScore(
        float $baseScore,
        array $environmental,
    ): float {
        $confidentialityRequirement =
            $environmental["confidentiality_requirement"] ?? 1.0;
        $integrityRequirement = $environmental["integrity_requirement"] ?? 1.0;
        $availabilityRequirement =
            $environmental["availability_requirement"] ?? 1.0;

        $environmentalScore =
            $baseScore *
            max(
                $confidentialityRequirement,
                $integrityRequirement,
                $availabilityRequirement,
            );

        return round(min($environmentalScore, 10), 1);
    }

    /**
     *
     *
     * @param float $score
     * @return string
     */
    public function getSeverityLevel(float $score): string
    {
        if ($score >= 9.0) {
            return self::CRITICAL;
        }
        if ($score >= 7.0) {
            return self::HIGH;
        }
        if ($score >= 4.0) {
            return self::MEDIUM;
        }
        if ($score >= 0.1) {
            return self::LOW;
        }
        return self::INFO;
    }

    /**
     *
     *
     * @param array $vulnerability
     * @return int
     */
    public function calculatePriority(array $vulnerability): int
    {
        $baseScore = $vulnerability["base_score"] ?? 0;
        $exploitAvailable = $vulnerability["exploit_available"] ?? false;
        $publicExploit = $vulnerability["public_exploit"] ?? false;
        $activelyExploited = $vulnerability["actively_exploited"] ?? false;
        $easilyReproducible = $vulnerability["easily_reproducible"] ?? false;
        $affectsAuth = $vulnerability["affects_authentication"] ?? false;
        $dataExposure = $vulnerability["data_exposure_risk"] ?? "LOW";
        $compliance = !empty($vulnerability["compliance_impact"]);

        $priority = $baseScore * 10;

        if ($activelyExploited) {
            $priority *= 1.5;
        }
        if ($publicExploit) {
            $priority *= 1.3;
        }
        if ($exploitAvailable) {
            $priority *= 1.2;
        }
        if ($easilyReproducible) {
            $priority *= 1.1;
        }
        if ($affectsAuth) {
            $priority *= 1.2;
        }
        if ($dataExposure === "HIGH") {
            $priority *= 1.3;
        }
        if ($compliance) {
            $priority *= 1.1;
        }

        return min((int) round($priority), 100);
    }

    /**
     *
     *
     * @param array $data
     * @return array
     */
    public function assessVulnerability(array $data): array
    {
        $baseScore = $this->calculateBaseScore($data["metrics"] ?? []);
        $severity = $this->getSeverityLevel($baseScore);

        $temporal = $data["temporal"] ?? [];
        $temporalScore = $this->calculateTemporalScore($baseScore, $temporal);

        $environmental = $data["environmental"] ?? [];
        $environmentalScore = $this->calculateEnvironmentalScore(
            $baseScore,
            $environmental,
        );

        $priority = $this->calculatePriority(
            array_merge($data, [
                "base_score" => $baseScore,
            ]),
        );

        return [
            "base_score" => $baseScore,
            "temporal_score" => $temporalScore,
            "environmental_score" => $environmentalScore,
            "severity" => $severity,
            "priority" => $priority,
            "cvss_vector" => $this->generateCvssVector($data["metrics"] ?? []),
            "risk_level" => $this->calculateRiskLevel($baseScore, $priority),
            "remediation_urgency" => $this->getRemediationUrgency(
                $severity,
                $priority,
            ),
        ];
    }

    /**
     *
     *
     * @param array $metrics
     * @return string
     */
    private function generateCvssVector(array $metrics): string
    {
        $av = $this->getVectorCode(
            "AV",
            $metrics["attack_vector"] ?? self::AV_NETWORK,
        );
        $ac = $this->getVectorCode(
            "AC",
            $metrics["attack_complexity"] ?? self::AC_LOW,
        );
        $pr = $this->getVectorCode(
            "PR",
            $metrics["privileges_required"] ?? self::PR_NONE,
        );
        $ui = $this->getVectorCode(
            "UI",
            $metrics["user_interaction"] ?? self::UI_NONE,
        );
        $s = $metrics["scope"] ?? self::SCOPE_UNCHANGED;
        $c = $this->getVectorCode(
            "C",
            $metrics["confidentiality_impact"] ?? self::IMPACT_HIGH,
        );
        $i = $this->getVectorCode(
            "I",
            $metrics["integrity_impact"] ?? self::IMPACT_HIGH,
        );
        $a = $this->getVectorCode(
            "A",
            $metrics["availability_impact"] ?? self::IMPACT_HIGH,
        );

        return "CVSS:3.1/AV:{$av}/AC:{$ac}/PR:{$pr}/UI:{$ui}/S:{$s}/C:{$c}/I:{$i}/A:{$a}";
    }

    /**
     *
     *
     * @param string $metric
     * @param float $value
     * @return string
     */
    private function getVectorCode(string $metric, float $value): string
    {
        $codes = [
            "AV" => [
                self::AV_NETWORK => "N",
                self::AV_ADJACENT => "A",
                self::AV_LOCAL => "L",
                self::AV_PHYSICAL => "P",
            ],
            "AC" => [
                self::AC_LOW => "L",
                self::AC_HIGH => "H",
            ],
            "PR" => [
                self::PR_NONE => "N",
                self::PR_LOW => "L",
                self::PR_HIGH => "H",
            ],
            "UI" => [
                self::UI_NONE => "N",
                self::UI_REQUIRED => "R",
            ],
            "C" => [
                self::IMPACT_HIGH => "H",
                self::IMPACT_LOW => "L",
                self::IMPACT_NONE => "N",
            ],
            "I" => [
                self::IMPACT_HIGH => "H",
                self::IMPACT_LOW => "L",
                self::IMPACT_NONE => "N",
            ],
            "A" => [
                self::IMPACT_HIGH => "H",
                self::IMPACT_LOW => "L",
                self::IMPACT_NONE => "N",
            ],
        ];

        return $codes[$metric][$value] ?? "N";
    }

    /**
     *
     *
     * @param float $score
     * @param int $priority
     * @return string
     */
    private function calculateRiskLevel(float $score, int $priority): string
    {
        if ($score >= 9.0 && $priority >= 80) {
            return "EXTREME";
        }
        if ($score >= 7.0 && $priority >= 60) {
            return "HIGH";
        }
        if ($score >= 4.0 && $priority >= 40) {
            return "MODERATE";
        }
        if ($score >= 0.1) {
            return "LOW";
        }
        return "INFORMATIONAL";
    }

    /**
     *
     *
     * @param string $severity
     * @param int $priority
     * @return string
     */
    private function getRemediationUrgency(
        string $severity,
        int $priority,
    ): string {
        if ($severity === self::CRITICAL && $priority >= 80) {
            return "IMMEDIATE (Fix within 24 hours)";
        }
        if (
            $severity === self::CRITICAL ||
            ($severity === self::HIGH && $priority >= 70)
        ) {
            return "URGENT (Fix within 7 days)";
        }
        if (
            $severity === self::HIGH ||
            ($severity === self::MEDIUM && $priority >= 50)
        ) {
            return "HIGH PRIORITY (Fix within 30 days)";
        }
        if ($severity === self::MEDIUM) {
            return "MEDIUM PRIORITY (Fix within 90 days)";
        }
        if ($severity === self::LOW) {
            return "LOW PRIORITY (Fix at convenience)";
        }
        return "INFORMATIONAL (No immediate action required)";
    }

    /**
     *
     *
     * @param string $severity
     * @return string
     */
    public function getSeverityColor(string $severity): string
    {
        return match ($severity) {
            self::CRITICAL => "#8B0000", // Dark Red
            self::HIGH => "#FF4500", // Orange Red
            self::MEDIUM => "#FFA500", // Orange
            self::LOW => "#FFD700", // Gold
            self::INFO => "#4682B4", // Steel Blue
            default => "#808080", // Gray
        };
    }

    /**
     *
     *
     * @param string $severity
     * @return string
     */
    public function getSeverityEmoji(string $severity): string
    {
        return match ($severity) {
            self::CRITICAL => "🔴",
            self::HIGH => "🟠",
            self::MEDIUM => "🟡",
            self::LOW => "🔵",
            self::INFO => "⚪",
            default => "⚫",
        };
    }
}
