<?php

class ThreatIntelligence
{
    private const Config = config("security-analyzer");
    private const EXPLOIT_DB_API = isset(
        self::Config["resources_thirdparty"]["dblist"],
    )
        ? self::Config["resources_thirdparty"]["dblist"]
        : "";
    private const CISA_KEV = isset(
        self::Config["resources_thirdparty"]["catalog"],
    )
        ? self::Config["resources_thirdparty"]["catalog"]
        : "";
    private const META_SPL = isset(
        self::Config["resources_thirdparty"]["metax"],
    )
        ? self::Config["resources_thirdparty"]["metax"]
        : "";

    public function isActivelyExploited(string $cveId): bool
    {
        $cache = cache()->remember(
            "exploited_{$cveId}",
            86400,
            function () use ($cveId) {
                try {
                    $response = Http::timeout(5)->get(self::CISA_KEV);
                    if ($response->successful()) {
                        $data = $response->json();
                        foreach ($data["vulnerabilities"] ?? [] as $vuln) {
                            if ($vuln["cveID"] === $cveId) {
                                return true;
                            }
                        }
                    }
                } catch (\Exception $e) {
                    Log::warning("CISA KEV check failed: {$e->getMessage()}");
                }
                return false;
            },
        );

        return $cache;
    }

    public function getExploitMaturity(string $cveId): string
    {
        $hasMetasploit = $this->checkMetasploitModule($cveId);
        $hasExploitDb = $this->checkExploitDb($cveId);
        $isActivelyExploited = $this->isActivelyExploited($cveId);

        if ($isActivelyExploited) {
            return "WEAPONIZED";
        }
        if ($hasMetasploit) {
            return "FUNCTIONAL";
        }
        if ($hasExploitDb) {
            return "PROOF_OF_CONCEPT";
        }

        return "UNPROVEN";
    }

    private function checkMetasploitModule(string $cveId): bool
    {
        return cache()->remember("msf_{$cveId}", 86400, function () use (
            $cveId,
        ) {
            try {
                $response = Http::timeout(5)->get(self::META_SPL, [
                    "q" => $cveId,
                    "type" => "metasploit",
                ]);
                return $response->successful() &&
                    str_contains($response->body(), $cveId);
            } catch (\Exception $e) {
                return false;
            }
        });
    }

    private function checkExploitDb(string $cveId): bool
    {
        return cache()->remember("edb_{$cveId}", 86400, function () use (
            $cveId,
        ) {
            try {
                $response = Http::timeout(5)->get(self::EXPLOIT_DB_API, [
                    "cve" => $cveId,
                ]);
                return $response->successful() &&
                    !empty($response->json()["data"] ?? []);
            } catch (\Exception $e) {
                return false;
            }
        });
    }

    public function getThreatActorTactics(array $vulnerability): array
    {
        // Map vulnerability to MITRE ATT&CK tactics
        $tactics = [];

        $typeToTactic = [
            "sql_injection" => [
                "T1190",
                "Initial Access - Exploit Public-Facing Application",
            ],
            "xss" => ["T1189", "Initial Access - Drive-by Compromise"],
            "command_injection" => [
                "T1059",
                "Execution - Command and Scripting Interpreter",
            ],
            "file_upload" => [
                "T1105",
                "Command and Control - Ingress Tool Transfer",
            ],
        ];

        foreach ($typeToTactic as $vulnType => $tactic) {
            if (stripos($vulnerability["type"], $vulnType) !== false) {
                $tactics[] = [
                    "technique_id" => $tactic[0],
                    "technique_name" => $tactic[1],
                    "tactic" => explode(" - ", $tactic[1])[0],
                ];
            }
        }

        return $tactics;
    }

    public function getRelatedIOCs(array $vulnerability): array
    {
        // Get Indicators of Compromise related to this vulnerability
        $iocs = [];

        if ($vulnerability["type"] === "sql_injection") {
            $iocs = [
                "patterns" => ["' OR '1'='1", "UNION SELECT", "'; DROP TABLE"],
                "user_agents" => ["sqlmap", "Havij"],
            ];
        }

        if ($vulnerability["type"] === "xss") {
            $iocs = [
                "patterns" => ["<script>alert(", "javascript:", "onerror="],
            ];
        }

        return $iocs;
    }
}
