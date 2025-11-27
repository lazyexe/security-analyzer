<?php

class ComplianceChecker
{
    private array $owaspTop10 = [
        "A01:2021" => "Broken Access Control",
        "A02:2021" => "Cryptographic Failures",
        "A03:2021" => "Injection",
        "A04:2021" => "Insecure Design",
        "A05:2021" => "Security Misconfiguration",
        "A06:2021" => "Vulnerable and Outdated Components",
        "A07:2021" => "Identification and Authentication Failures",
        "A08:2021" => "Software and Data Integrity Failures",
        "A09:2021" => "Security Logging and Monitoring Failures",
        "A10:2021" => "Server-Side Request Forgery",
    ];

    public function mapToCompliance(array $vulnerability): array
    {
        $mappings = [];
        if (isset($vulnerability["owasp"])) {
            $mappings["OWASP_TOP_10"] = [
                "category" => $vulnerability["owasp"],
                "name" =>
                    $this->owaspTop10[$vulnerability["owasp"]] ?? "Unknown",
            ];
        }

        $pciDss = $this->mapToPCIDSS($vulnerability);
        if (!empty($pciDss)) {
            $mappings["PCI_DSS"] = $pciDss;
        }

        if ($vulnerability["data_exposure_risk"] === "HIGH") {
            $mappings["GDPR"] = [
                "articles" => ["Article 32 - Security of processing"],
                "risk" => "Personal data breach",
            ];
        }

        return $mappings;
    }

    private function mapToPCIDSS(array $vulnerability): array
    {
        $requirements = [];

        if ($vulnerability["type"] === "sql_injection") {
            $requirements[] = "6.5.1 - Injection flaws";
        }
        if ($vulnerability["type"] === "xss") {
            $requirements[] = "6.5.7 - Cross-site scripting";
        }
        if (stripos($vulnerability["type"], "authentication") !== false) {
            $requirements[] = "8.2 - User authentication";
        }
        if (stripos($vulnerability["type"], "encryption") !== false) {
            $requirements[] = "4.1 - Use strong cryptography";
        }

        return $requirements;
    }

    public function checkOWASPCoverage(array $findings): array
    {
        $coverage = [];

        foreach ($this->owaspTop10 as $code => $name) {
            $found = array_filter(
                $findings,
                fn($f) => ($f["owasp"] ?? "") === $code,
            );

            $coverage[$code] = [
                "name" => $name,
                "vulnerabilities_found" => count($found),
                "covered" => count($found) > 0,
            ];
        }

        return $coverage;
    }

    public function checkPCIDSS(array $findings): array
    {
        return [
            "compliant" => false,
            "findings" => count($findings),
            "critical_issues" => count(
                array_filter(
                    $findings,
                    fn($f) => $f["severity"] === "CRITICAL",
                ),
            ),
            "requirements_violated" => $this->getViolatedRequirements(
                $findings,
            ),
        ];
    }

    private function getViolatedRequirements(array $findings): array
    {
        $violated = [];

        foreach ($findings as $finding) {
            $reqs = $this->mapToPCIDSS($finding);
            $violated = array_merge($violated, $reqs);
        }

        return array_unique($violated);
    }

    public function generateComplianceReport(
        string $standard,
        array $findings,
    ): array {
        switch ($standard) {
            case "OWASP":
                return $this->checkOWASPCoverage($findings);
            case "PCI-DSS":
                return $this->checkPCIDSS($findings);
            default:
                return [];
        }
    }
}
