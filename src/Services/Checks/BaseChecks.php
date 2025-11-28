<?php

namespace SecurityAnalyzer\Checks;
use SecurityAnalyzer\Core\SeverityScorer;
use SecurityAnalyzer\Core\VulnerabilityDatabase;

abstract class BaseChecks
{
    protected SeverityScorer $scorer;
    protected VulnerabilityDatabase $vulnDb;

    public function __construct()
    {
        $this->scorer = new SeverityScorer();
        $this->vulnDb = new VulnerabilityDatabase();
    }

    final public function loadFile(string $path): string
    {
        if (!file_exists($path)) {
            return "";
        }
        return file_get_contents($path);
    }

    final protected function scanLines(string $content): array
    {
        return explode("\n", $content);
    }

    final protected function scanPatterns(
        array $lines,
        string $path,
        array $patterns,
        string $defaultMethod = "Pattern Matching",
    ): array {
        $findings = [];

        foreach ($lines as $lineNum => $line) {
            foreach ($patterns as $pattern => $config) {
                if (preg_match($pattern, $line)) {
                    $findings[] = $this->createFinding(
                        $config["name"],
                        $path,
                        $lineNum + 1,
                        $config["severity"],
                        $config["method"] ?? $defaultMethod,
                        $config["extra"] ?? [],
                    );
                }
            }
        }

        return $findings;
    }

    protected function createFinding(
        string $name,
        string $file,
        int $line,
        string $severity,
        string $method,
        array $extra = [],
    ): array {
        $vulnInfo = $this->vulnDb->getVulnerabilityInfo("sql_injection");

        $assessment = $this->scorer->assessVulnerability([
            "metrics" => [
                "attack_vector" => SeverityScorer::AV_NETWORK,
                "attack_complexity" => SeverityScorer::AC_LOW,
                "privileges_required" => SeverityScorer::PR_NONE,
                "user_interaction" => SeverityScorer::UI_NONE,
                "confidentiality_impact" => SeverityScorer::IMPACT_HIGH,
                "integrity_impact" => SeverityScorer::IMPACT_HIGH,
                "availability_impact" => SeverityScorer::IMPACT_HIGH,
            ],
            "exploit_available" => true,
            "data_exposure_risk" => "HIGH",
        ]);

        return [
            "type" => static::class,
            "name" => $name,
            "file" => $file,
            "line" => $line,
            "severity" => $severity,
            "base_score" => $assessment["base_score"],
            "cvss_vector" => $assessment["cvss_vector"],
            "priority" => $assessment["priority"],
            "cwe_id" => $vulnInfo["cwe_id"] ?? "CWE-89",
            "owasp" => $vulnInfo["owasp"] ?? "A03:2021",
            "detection_method" => $method,
            "description" => "Injection vulnerability detected.",
            "data_flow" => $extra["flow_path"] ?? [],
        ];
    }
}
