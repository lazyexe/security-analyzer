<?php
namespace SecurityAnalyzer\Checks\Injection;

use SecurityAnalyzer\Checks\BaseChecks;

class NoSqlInjection extends BaseChecks
{
    public function check(string $path): array
    {
        $content = $this->loadFile($path);

        $patterns = [
            '/\$where.*\$_(?:GET|POST|REQUEST)/' => [
                "name" => 'MongoDB $where injection',
                "severity" => "CRITICAL",
            ],
            '/\[\'\$(?:ne|gt|lt|regex)\'\].*\$_/' => [
                "name" => "MongoDB operator injection",
                "severity" => "CRITICAL",
            ],
            '/->where\(\[.*\$_(?:GET|POST)/' => [
                "name" => "NoSQL query injection",
                "severity" => "CRITICAL",
            ],
        ];

        return $this->scanPatterns(
            $this->scanLines($content),
            $path,
            $patterns,
        );
    }
}
