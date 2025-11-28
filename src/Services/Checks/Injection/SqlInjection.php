<?php
namespace SecurityAnalyzer\Checks\Injection;

use SecurityAnalyzer\Core\ASTParser;
use SecurityAnalyzer\Core\DataFlowAnalyzer;
use SecurityAnalyzer\Checks\BaseChecks;

class SqlInjection extends BaseChecks
{
    private ASTParser $astParser;
    private DataFlowAnalyzer $dataFlowAnalyzer;

    public function __construct()
    {
        parent::__construct();
        $this->astParser = new ASTParser();
        $this->dataFlowAnalyzer = new DataFlowAnalyzer();
    }

    public function check(string $path): array
    {
        $findings = [];

        $content = $this->loadFile($path);
        if ($content === null) {
            return $findings;
        }

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

        $findings = array_merge(
            $findings,
            $this->detectPatterns($content, $path),
        );
        $findings = array_merge(
            $findings,
            $this->checkLaravelSpecific($content, $path),
        );
        $findings = array_merge(
            $findings,
            $this->detectRawSql($content, $path),
        );

        return $findings;
    }

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

    protected function createFinding(
        string $name,
        string $file,
        int $line,
        string $severity,
        string $method,
        array $extra = [],
    ): array {
        // ✅ Maps your original output to shared engine
        return $this->createBaseFinding(
            $name,
            $file,
            $line,
            $severity,
            $method,
            $extra,
        );
    }
}
