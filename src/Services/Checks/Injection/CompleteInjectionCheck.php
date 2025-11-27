<?php

namespace SecurityAnalyzer\Checks\Injection;

use SecurityAnalyzer\Core\ASTParser;
use SecurityAnalyzer\Core\DataFlowAnalyzer;
use SecurityAnalyzer\Core\SeverityScorer;
use SecurityAnalyzer\Core\VulnerabilityDatabase;

class SqlInjectionCheck
{
    private ASTParser $astParser;
    private DataFlowAnalyzer $dataFlowAnalyzer;
    private SeverityScorer $scorer;
    private VulnerabilityDatabase $vulnDb;

    public function __construct()
    {
        $this->astParser = new ASTParser();
        $this->dataFlowAnalyzer = new DataFlowAnalyzer();
        $this->scorer = new SeverityScorer();
        $this->vulnDb = new VulnerabilityDatabase();
    }

    /**
     *
     *
     * @param string $path
     * @return array
     */
    public function check(string $path): array
    {
        $findings = [];

        if (!file_exists($path)) {
            return $findings;
        }

        $content = file_get_contents($path);
        $ast = $this->astParser->parseFile($path);
        if ($ast) {
            $astFindings = $this->astParser->findSqlInjectionVulnerabilities(
                $ast,
            );
            foreach ($astFindings as $finding) {
                $findings[] = $this->createFinding(
                    $finding["type"],
                    $path,
                    $finding["line"],
                    "CRITICAL",
                    "AST Analysis",
                );
            }
        }

        $dataFlows = $this->dataFlowAnalyzer->analyzeFile($path);
        foreach ($dataFlows as $flow) {
            if ($flow["type"] === "sql") {
                $findings[] = $this->createFinding(
                    "SQL Injection via {$flow["tainted_var"]}",
                    $path,
                    $flow["sink_line"],
                    "CRITICAL",
                    "Data Flow Analysis",
                    $flow,
                );
            }
        }

        $patternFindings = $this->detectPatterns($content, $path);
        $findings = array_merge($findings, $patternFindings);

        $laravelFindings = $this->checkLaravelSpecific($content, $path);
        $findings = array_merge($findings, $laravelFindings);

        $rawSqlFindings = $this->detectRawSql($content, $path);
        $findings = array_merge($findings, $rawSqlFindings);

        return $findings;
    }

    /**
     *
     *
     * @param string $content
     * @param string $path
     * @return array
     */
    private function detectPatterns(string $content, string $path): array
    {
        $findings = [];
        $lines = explode("\n", $content);

        $patterns = [
            [
                "pattern" => '/DB::raw\s*\([^)]*\.\s*\$[^)]*\)/',
                "name" => "DB::raw with string concatenation",
                "severity" => "CRITICAL",
                "cwe" => "CWE-89",
            ],
            [
                "pattern" =>
                    '/DB::select\s*\(\s*[\'"].*\{.*\$.*\}.*[\'"]\s*\)/',
                "name" => "DB::select with variable interpolation",
                "severity" => "CRITICAL",
                "cwe" => "CWE-89",
            ],
            [
                "pattern" => '/mysqli_query\s*\([^,]+,\s*[\'"].*\.\s*\$/',
                "name" => "mysqli_query with concatenation",
                "severity" => "CRITICAL",
                "cwe" => "CWE-89",
            ],
            [
                "pattern" => '/pg_query\s*\([^,]+,\s*[\'"].*\.\s*\$/',
                "name" => "pg_query with concatenation",
                "severity" => "CRITICAL",
                "cwe" => "CWE-89",
            ],
            [
                "pattern" => '/\$pdo->exec\s*\([^)]*\$_(?:GET|POST|REQUEST)/',
                "name" => "PDO exec with superglobal",
                "severity" => "CRITICAL",
                "cwe" => "CWE-89",
            ],
        ];

        foreach ($lines as $lineNum => $line) {
            foreach ($patterns as $patternData) {
                if (preg_match($patternData["pattern"], $line)) {
                    $findings[] = $this->createFinding(
                        $patternData["name"],
                        $path,
                        $lineNum + 1,
                        $patternData["severity"],
                        "Pattern Matching",
                        ["cwe" => $patternData["cwe"]],
                    );
                }
            }
        }

        return $findings;
    }

    /**
     *
     *
     * @param string $content
     * @param string $path
     * @return array
     */
    private function checkLaravelSpecific(string $content, string $path): array
    {
        $findings = [];
        $lines = explode("\n", $content);

        $patterns = [
            [
                "pattern" => '/->whereRaw\s*\([^)]*\$(?!.*\?)/',
                "name" => "whereRaw without parameter binding",
                "severity" => "CRITICAL",
            ],
            [
                "pattern" => '/->selectRaw\s*\([^)]*\$(?!.*\?)/',
                "name" => "selectRaw without parameter binding",
                "severity" => "CRITICAL",
            ],
            [
                "pattern" => '/->havingRaw\s*\([^)]*\$(?!.*\?)/',
                "name" => "havingRaw without parameter binding",
                "severity" => "CRITICAL",
            ],
            [
                "pattern" => '/->orderByRaw\s*\([^)]*\$(?!.*\?)/',
                "name" => "orderByRaw without parameter binding",
                "severity" => "HIGH",
            ],
            [
                "pattern" => "/->where\s*\(\s*DB::raw/",
                "name" => "where clause with DB::raw",
                "severity" => "HIGH",
            ],
        ];

        foreach ($lines as $lineNum => $line) {
            foreach ($patterns as $patternData) {
                if (preg_match($patternData["pattern"], $line)) {
                    $findings[] = $this->createFinding(
                        $patternData["name"],
                        $path,
                        $lineNum + 1,
                        $patternData["severity"],
                        "Laravel Analysis",
                    );
                }
            }
        }

        return $findings;
    }

    /**
     *
     *
     * @param string $content
     * @param string $path
     * @return array
     */
    private function detectRawSql(string $content, string $path): array
    {
        $findings = [];
        $lines = explode("\n", $content);

        foreach ($lines as $lineNum => $line) {
            if (
                preg_match(
                    '/[\'"](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER).*\$/',
                    $line,
                )
            ) {
                if (
                    !preg_match("/\?/", $line) &&
                    !preg_match("/:\w+/", $line)
                ) {
                    $findings[] = $this->createFinding(
                        "Raw SQL query with variable interpolation",
                        $path,
                        $lineNum + 1,
                        "CRITICAL",
                        "SQL Keyword Detection",
                    );
                }
            }
            if (preg_match('/UNION.*SELECT.*\$/', $line)) {
                $findings[] = $this->createFinding(
                    "Potential UNION-based SQL injection",
                    $path,
                    $lineNum + 1,
                    "CRITICAL",
                    "UNION Attack Detection",
                );
            }
            if (preg_match('/(SLEEP|WAITFOR|BENCHMARK).*\$/', $line)) {
                $findings[] = $this->createFinding(
                    "Potential time-based blind SQL injection",
                    $path,
                    $lineNum + 1,
                    "CRITICAL",
                    "Time-Based Attack Detection",
                );
            }
        }

        return $findings;
    }

    /**
     *
     *
     * @param string $name
     * @param string $file
     * @param int $line
     * @param string $severity
     * @param string $method
     * @param array $extra
     * @return array
     */
    private function createFinding(
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
            "type" => "SQL Injection",
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
            "description" =>
                "SQL injection vulnerability detected. User input may be directly concatenated into SQL queries without proper sanitization or parameterization.",
            "impact" =>
                "An attacker could execute arbitrary SQL commands, potentially leading to:\n- Unauthorized data access\n- Data modification or deletion\n- Authentication bypass\n- Complete database compromise",
            "remediation" =>
                "Use parameterized queries or prepared statements:\n\n// Bad:\nDB::raw('SELECT * FROM users WHERE id = ' . \$id);\n\n// Good:\nDB::table('users')->where('id', \$id)->get();\n// Or:\nDB::select('SELECT * FROM users WHERE id = ?', [\$id]);",
            "references" => [
                "OWASP SQL Injection" =>
                    "https://owasp.org/www-community/attacks/SQL_Injection",
                "Laravel Query Builder" => "https://laravel.com/docs/queries",
            ],
            "data_flow" => $extra["flow_path"] ?? [],
        ];
    }
}

class NoSqlInjectionCheck
{
    public function check(string $path): array
    {
        $findings = [];
        $content = file_get_contents($path);

        // MongoDB injection patterns
        $patterns = [
            '/\$where.*\$_(?:GET|POST|REQUEST)/' => 'MongoDB $where injection',
            '/\[\'\$(?:ne|gt|lt|regex)\'\].*\$_/' =>
                "MongoDB operator injection",
            '/->where\(\[.*\$_(?:GET|POST)/' => "NoSQL query injection",
        ];

        foreach ($patterns as $pattern => $name) {
            if (preg_match($pattern, $content, $matches)) {
                $findings[] = $this->createFinding($name, $path, "CRITICAL");
            }
        }

        return $findings;
    }
}

class LdapInjectionCheck
{
    public function check(string $path): array
    {
        $findings = [];
        $content = file_get_contents($path);

        $patterns = [
            '/ldap_search\([^)]*\$(?!.*ldap_escape)/' =>
                "LDAP search without escaping",
            '/ldap_bind\([^)]*\$/' => "LDAP bind with user input",
        ];

        foreach ($patterns as $pattern => $name) {
            if (preg_match($pattern, $content)) {
                $findings[] = $this->createFinding($name, $path, "HIGH");
            }
        }

        return $findings;
    }
}

class XmlInjectionCheck
{
    public function check(string $path): array
    {
        $findings = [];
        $content = file_get_contents($path);

        // XXE (XML External Entity) patterns
        $patterns = [
            '/simplexml_load_string\([^)]*\$(?!.*LIBXML_NOENT)/' =>
                "XXE via simplexml_load_string",
            '/DOMDocument.*loadXML\([^)]*\$/' => "XXE via DOMDocument::loadXML",
            '/xml_parse\([^)]*\$/' => "XXE via xml_parse",
        ];

        // Check if external entity loading is disabled
        if (!preg_match("/libxml_disable_entity_loader\(true\)/", $content)) {
            $findings[] = $this->createFinding(
                "External entity loader not disabled",
                $path,
                "HIGH",
            );
        }

        foreach ($patterns as $pattern => $name) {
            if (preg_match($pattern, $content)) {
                $findings[] = $this->createFinding($name, $path, "HIGH");
            }
        }

        return $findings;
    }
}

class XPathInjectionCheck
{
    public function check(string $path): array
    {
        $findings = [];
        $content = file_get_contents($path);

        if (preg_match('/->query\([^)]*\$/', $content)) {
            $findings[] = $this->createFinding(
                "XPath query with user input",
                $path,
                "HIGH",
            );
        }

        return $findings;
    }
}

class CommandInjectionCheck
{
    public function check(string $path): array
    {
        $findings = [];
        $content = file_get_contents($path);

        $dangerousFunctions = [
            "exec",
            "shell_exec",
            "system",
            "passthru",
            "proc_open",
            "popen",
            "pcntl_exec",
        ];

        foreach ($dangerousFunctions as $func) {
            if (preg_match("/{$func}\s*\([^)]*\\\$/", $content)) {
                if (!preg_match("/escapeshellarg|escapeshellcmd/", $content)) {
                    $findings[] = $this->createFinding(
                        "Command injection via {$func}()",
                        $path,
                        "CRITICAL",
                    );
                }
            }
        }

        return $findings;
    }
}

class CodeInjectionCheck
{
    public function check(string $path): array
    {
        $findings = [];
        $content = file_get_contents($path);

        $patterns = [
            '/eval\s*\([^)]*\$/' => "eval() with user input - CRITICAL",
            "/create_function\s*\(/" =>
                "create_function() is deprecated and dangerous",
            '/assert\s*\([^)]*\$/' => "assert() with user input",
            '/unserialize\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/' =>
                "Insecure deserialization",
            "/preg_replace.*\/e/" =>
                "preg_replace with /e modifier (code execution)",
        ];

        foreach ($patterns as $pattern => $name) {
            if (preg_match($pattern, $content)) {
                $findings[] = $this->createFinding($name, $path, "CRITICAL");
            }
        }

        return $findings;
    }
}

class TemplateInjectionCheck
{
    public function check(string $path): array
    {
        $findings = [];
        $content = file_get_contents($path);
        $patterns = [
            '/\{\{.*\$_(?:GET|POST|REQUEST).*\}\}/' =>
                "Template injection in Blade/Twig",
            '/render\([^)]*\$_(?:GET|POST)/' =>
                "Template render with user input",
        ];

        foreach ($patterns as $pattern => $name) {
            if (preg_match($pattern, $content)) {
                $findings[] = $this->createFinding($name, $path, "HIGH");
            }
        }

        return $findings;
    }
}
