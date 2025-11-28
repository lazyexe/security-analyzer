<?php

namespace SecurityAnalyzer\Core;

/**
 *
 *
 */
class AttackVectorAnalyzer
{
    private array $vulnerabilities = [];
    private array $attackGraph = [];

    public function analyzeAttackVectors(array $vulnerabilities): array
    {
        $this->vulnerabilities = $vulnerabilities;
        $this->buildAttackGraph();

        return [
            "entry_points" => $this->identifyEntryPoints(),
            "attack_chains" => $this->buildAttackChains(),
            "critical_paths" => $this->findCriticalPaths(),
            "privilege_escalation" => $this->findPrivilegeEscalationPaths(),
            "lateral_movement" => $this->identifyLateralMovementOptions(),
        ];
    }

    private function identifyEntryPoints(): array
    {
        $entryPoints = [];

        foreach ($this->vulnerabilities as $vuln) {
            if (
                $vuln["attack_vector"] === "NETWORK" &&
                $vuln["privileges_required"] === "NONE"
            ) {
                $entryPoints[] = [
                    "vulnerability" => $vuln["name"],
                    "location" => $vuln["file"],
                    "attack_complexity" => $vuln["attack_complexity"],
                    "potential_impact" => $this->calculateImpact($vuln),
                ];
            }
        }

        usort(
            $entryPoints,
            fn($a, $b) => $b["potential_impact"] <=> $a["potential_impact"],
        );

        return $entryPoints;
    }

    private function buildAttackChains(): array
    {
        $chains = [];

        $sqlInjections = $this->findVulnerabilitiesByType("sql_injection");
        $rceVulns = $this->findVulnerabilitiesByType("command_injection");

        foreach ($sqlInjections as $sql) {
            foreach ($rceVulns as $rce) {
                if ($this->canChain($sql, $rce)) {
                    $chains[] = [
                        "chain_type" =>
                            "SQL Injection -> Remote Code Execution",
                        "steps" => [
                            [
                                "step" => 1,
                                "action" => "Exploit SQL injection",
                                "vuln" => $sql,
                            ],
                            [
                                "step" => 2,
                                "action" => "Write PHP webshell to disk",
                                "method" => "INTO OUTFILE",
                            ],
                            [
                                "step" => 3,
                                "action" => "Execute system commands",
                                "vuln" => $rce,
                            ],
                        ],
                        "severity" => "CRITICAL",
                        "complexity" => "LOW",
                    ];
                }
            }
        }

        $xssVulns = $this->findVulnerabilitiesByType("xss");
        $weakSessions = $this->findVulnerabilitiesByType("session_management");

        foreach ($xssVulns as $xss) {
            foreach ($weakSessions as $session) {
                $chains[] = [
                    "chain_type" =>
                        "XSS -> Session Hijacking -> Account Takeover",
                    "steps" => [
                        [
                            "step" => 1,
                            "action" => "Inject malicious JavaScript",
                            "vuln" => $xss,
                        ],
                        [
                            "step" => 2,
                            "action" => "Steal session cookie",
                            "method" => "document.cookie",
                        ],
                        [
                            "step" => 3,
                            "action" => "Hijack user session",
                            "vuln" => $session,
                        ],
                    ],
                    "severity" => "HIGH",
                    "complexity" => "LOW",
                ];
            }
        }

        return $chains;
    }

    private function findCriticalPaths(): array
    {
        $criticalPaths = [];

        $authBypass = $this->findVulnerabilitiesByType("authentication_bypass");
        $privEsc = $this->findVulnerabilitiesByType("privilege_escalation");

        if (!empty($authBypass) || !empty($privEsc)) {
            $criticalPaths[] = [
                "target" => "Administrative Access",
                "vulnerabilities" => array_merge($authBypass, $privEsc),
                "risk" => "EXTREME",
            ];
        }

        $dataExposure = $this->findVulnerabilitiesByType("data_exposure");
        $idor = $this->findVulnerabilitiesByType("idor");

        if (!empty($dataExposure) || !empty($idor)) {
            $criticalPaths[] = [
                "target" => "Sensitive Data Exfiltration",
                "vulnerabilities" => array_merge($dataExposure, $idor),
                "risk" => "CRITICAL",
            ];
        }

        return $criticalPaths;
    }

    private function findPrivilegeEscalationPaths(): array
    {
        $paths = [];

        $idorVulns = $this->findVulnerabilitiesByType("idor");
        foreach ($idorVulns as $idor) {
            $paths[] = [
                "type" => "Horizontal Privilege Escalation",
                "method" => "IDOR",
                "description" =>
                    'Access other users\' resources by manipulating IDs',
                "vulnerability" => $idor,
                "impact" => "Access to all user data",
            ];
        }

        $roleVulns = $this->findVulnerabilitiesByType("broken_access_control");
        foreach ($roleVulns as $role) {
            $paths[] = [
                "type" => "Vertical Privilege Escalation",
                "method" => "Role Manipulation",
                "description" => "Escalate to administrator privileges",
                "vulnerability" => $role,
                "impact" => "Full system compromise",
            ];
        }

        return $paths;
    }

    private function identifyLateralMovementOptions(): array
    {
        $options = [];

        $ssrfVulns = $this->findVulnerabilitiesByType("ssrf");
        foreach ($ssrfVulns as $ssrf) {
            $options[] = [
                "method" => "SSRF",
                "description" =>
                    "Access internal services from compromised server",
                "targets" => [
                    "Internal APIs",
                    "Database servers",
                    "Cloud metadata",
                ],
                "vulnerability" => $ssrf,
            ];
        }

        return $options;
    }

    private function findVulnerabilitiesByType(string $type): array
    {
        return array_filter(
            $this->vulnerabilities,
            fn($v) => stripos($v["type"], $type) !== false,
        );
    }

    private function canChain(array $vuln1, array $vuln2): bool
    {
        return str_contains($vuln1["file"], "Controller") ||
            str_contains($vuln2["file"], "Controller");
    }

    private function calculateImpact(array $vuln): int
    {
        $impact = 0;
        $impact += ($vuln["base_score"] ?? 0) * 10;
        $impact += $vuln["priority"] ?? 0;
        return $impact;
    }

    private function buildAttackGraph(): void
    {
        $this->attackGraph = [];

        foreach ($this->vulnerabilities as $vuln) {
            $node = [
                "id" => $vuln["name"],
                "type" => $vuln["type"],
                "severity" => $vuln["severity"],
                "dependencies" => [],
                "enables" => [],
            ];

            $this->attackGraph[$vuln["name"]] = $node;
        }
    }
}
?>
