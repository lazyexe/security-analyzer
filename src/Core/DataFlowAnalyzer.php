<?php

namespace SecurityAnalyzer\Core;

/**
 *
 *
 */
class DataFlowAnalyzer
{
    private array $taintedVariables = [];
    private array $dataFlow = [];

    private const TAINT_SOURCES = [
        '$_GET',
        '$_POST',
        '$_REQUEST',
        '$_COOKIE',
        '$_SERVER',
        '$_FILES',
        "Request::input",
        "Request::get",
        "Request::post",
        "Request::all",
        "request()->input",
        "request()->get",
        "Input::get",
    ];

    private const DANGEROUS_SINKS = [
        "sql" => [
            "DB::raw",
            "whereRaw",
            "selectRaw",
            "havingRaw",
            "mysqli_query",
            "pg_query",
        ],
        "command" => [
            "exec",
            "shell_exec",
            "system",
            "passthru",
            "proc_open",
            "popen",
        ],
        "file" => [
            "file_get_contents",
            "readfile",
            "include",
            "require",
            "fopen",
        ],
        "eval" => ["eval", "create_function", "assert"],
        "xss" => ["echo", "print", "printf"],
        "deserialization" => ["unserialize", "yaml_parse"],
        "ldap" => ["ldap_search", "ldap_bind"],
        "xml" => ["simplexml_load_string", "DOMDocument::loadXML"],
    ];

    private const SANITIZERS = [
        "htmlspecialchars",
        "htmlentities",
        "strip_tags",
        "addslashes",
        "mysqli_real_escape_string",
        "pg_escape_string",
        "e()",
        "escape",
        "filter_var",
        "filter_input",
        "preg_replace",
        "str_replace",
        "intval",
        "floatval",
        "boolval",
        "strval",
    ];

    /**
     *
     *
     * @param string $code
     * @return array
     */
    public function analyzeDataFlow(string $code): array
    {
        $this->taintedVariables = [];
        $this->dataFlow = [];

        $lines = explode("\n", $code);

        foreach ($lines as $lineNum => $line) {
            $this->analyzeLine($line, $lineNum + 1);
        }

        return $this->dataFlow;
    }

    /**
     *
     *
     * @param string $line
     * @param int $lineNum
     */
    private function analyzeLine(string $line, int $lineNum): void
    {
        $this->trackTaintedAssignments($line, $lineNum);
        $this->checkVulnerableSinks($line, $lineNum);
    }

    /**
     *
     *
     * @param string $line
     * @param int $lineNum
     */
    private function trackTaintedAssignments(string $line, int $lineNum): void
    {
        if (preg_match('/(\$\w+)\s*=\s*(.+);/', $line, $matches)) {
            $variable = $matches[1];
            $source = $matches[2];
            if ($this->isTaintedSource($source)) {
                $this->taintedVariables[$variable] = [
                    "line" => $lineNum,
                    "source" => $source,
                    "sanitized" => false,
                ];
            }

            foreach ($this->taintedVariables as $taintedVar => $info) {
                if (strpos($source, $taintedVar) !== false) {
                    $isSanitized = $this->isSanitized($source);
                    $this->taintedVariables[$variable] = [
                        "line" => $lineNum,
                        "source" => $taintedVar,
                        "sanitized" => $isSanitized,
                    ];
                }
            }
        }
    }

    /**
     *
     *
     * @param string $source
     * @return bool
     */
    private function isTaintedSource(string $source): bool
    {
        foreach (self::TAINT_SOURCES as $taintSource) {
            if (strpos($source, $taintSource) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     *
     *
     * @param string $code
     * @return bool
     */
    private function isSanitized(string $code): bool
    {
        foreach (self::SANITIZERS as $sanitizer) {
            if (strpos($code, $sanitizer) !== false) {
                return true;
            }
        }
        return false;
    }

    /**
     *
     *
     * @param string $line
     * @param int $lineNum
     */
    private function checkVulnerableSinks(string $line, int $lineNum): void
    {
        foreach (self::DANGEROUS_SINKS as $category => $sinks) {
            foreach ($sinks as $sink) {
                if (strpos($line, $sink) !== false) {
                    foreach ($this->taintedVariables as $taintedVar => $info) {
                        if (
                            strpos($line, $taintedVar) !== false &&
                            !$info["sanitized"]
                        ) {
                            $this->dataFlow[] = [
                                "type" => $category,
                                "sink" => $sink,
                                "tainted_var" => $taintedVar,
                                "source_line" => $info["line"],
                                "sink_line" => $lineNum,
                                "severity" => $this->getSeverity($category),
                                "flow_path" => $this->buildFlowPath(
                                    $taintedVar,
                                    $lineNum,
                                ),
                            ];
                        }
                    }
                }
            }
        }
    }

    /**
     *
     *
     * @param string $category
     * @return string
     */
    private function getSeverity(string $category): string
    {
        $severityMap = [
            "sql" => "CRITICAL",
            "command" => "CRITICAL",
            "eval" => "CRITICAL",
            "deserialization" => "CRITICAL",
            "file" => "HIGH",
            "xss" => "HIGH",
            "ldap" => "HIGH",
            "xml" => "HIGH",
        ];

        return $severityMap[$category] ?? "MEDIUM";
    }

    /**
     *
     *
     * @param string $variable
     * @param int $sinkLine
     * @return array
     */
    private function buildFlowPath(string $variable, int $sinkLine): array
    {
        $path = [];

        if (isset($this->taintedVariables[$variable])) {
            $info = $this->taintedVariables[$variable];
            $path[] = [
                "step" => "SOURCE",
                "line" => $info["line"],
                "description" => "Untrusted input from {$info["source"]}",
            ];
            $path[] = [
                "step" => "ASSIGNMENT",
                "line" => $info["line"],
                "description" => "Assigned to {$variable}",
            ];
            $path[] = [
                "step" => "SINK",
                "line" => $sinkLine,
                "description" => "Used in dangerous function",
            ];
        }

        return $path;
    }

    /**
     *
     *
     * @param string $filePath
     * @return array
     */
    public function analyzeFile(string $filePath): array
    {
        if (!file_exists($filePath)) {
            return [];
        }

        $code = file_get_contents($filePath);
        return $this->analyzeDataFlow($code);
    }

    /**
     *
     *
     * @param array $dataFlows
     * @return array
     */
    public function generateReport(array $dataFlows): array
    {
        $report = [
            "total_vulnerabilities" => count($dataFlows),
            "by_severity" => [
                "CRITICAL" => 0,
                "HIGH" => 0,
                "MEDIUM" => 0,
            ],
            "by_type" => [],
            "vulnerabilities" => [],
        ];

        foreach ($dataFlows as $flow) {
            $severity = $flow["severity"];
            $report["by_severity"][$severity]++;
            $type = $flow["type"];
            if (!isset($report["by_type"][$type])) {
                $report["by_type"][$type] = 0;
            }
            $report["by_type"][$type]++;
            $report["vulnerabilities"][] = [
                "title" => ucfirst($type) . " Injection via Tainted Data",
                "severity" => $severity,
                "type" => $type,
                "sink_function" => $flow["sink"],
                "tainted_variable" => $flow["tainted_var"],
                "data_flow" => $flow["flow_path"],
                "recommendation" => $this->getRecommendation($type),
            ];
        }

        return $report;
    }

    /**
     *
     *
     * @param string $type
     * @return string
     */
    private function getRecommendation(string $type): string
    {
        $recommendations = [
            "sql" =>
                "Use parameterized queries or Eloquent ORM instead of raw SQL with user input",
            "command" =>
                "Avoid executing system commands with user input. If necessary, use escapeshellarg()",
            "file" =>
                "Validate and sanitize file paths. Use whitelisting for allowed paths",
            "eval" =>
                "Never use eval() or similar functions with user input. Refactor code to avoid dynamic execution",
            "xss" =>
                'Always escape output using htmlspecialchars() or Blade\'s {{ }} syntax',
            "deserialization" =>
                "Avoid unserialize() with user input. Use JSON instead",
            "ldap" => "Escape LDAP special characters before using in queries",
            "xml" =>
                "Disable external entity loading when parsing XML from user input",
        ];

        return $recommendations[$type] ??
            "Sanitize and validate all user input before use";
    }

    /**
     *
     *
     * @param string $code
     * @param string $pattern
     * @return bool
     */
    public function hasVulnerabilityPattern(string $code, string $pattern): bool
    {
        $flows = $this->analyzeDataFlow($code);

        foreach ($flows as $flow) {
            if ($flow["type"] === $pattern) {
                return true;
            }
        }

        return false;
    }

    /**
     *
     *
     * @return array
     */
    public function getTaintedVariables(): array
    {
        return $this->taintedVariables;
    }

    /**
     *
     */
    public function reset(): void
    {
        $this->taintedVariables = [];
        $this->dataFlow = [];
    }
}
