<?php

namespace SecurityAnalyzer\Checks\Injection;
use SecurityAnalyzer\Checks\BaseChecks;

class CodeInjection extends BaseChecks
{
    public function check(string $path): array
    {
        $content = $this->loadFile($path);

        $patterns = [
            '/eval\s*\([^)]*\$/' => [
                "name" => "eval() with user input - CRITICAL",
                "severity" => "CRITICAL",
            ],
            "/create_function\s*\(/" => [
                "name" => "create_function() is deprecated and dangerous",
                "severity" => "CRITICAL",
            ],
            '/assert\s*\([^)]*\$/' => [
                "name" => "assert() with user input",
                "severity" => "CRITICAL",
            ],
            '/unserialize\s*\([^)]*\$_(?:GET|POST|REQUEST|COOKIE)/' => [
                "name" => "Insecure deserialization",
                "severity" => "CRITICAL",
            ],
            "/preg_replace.*\/e/" => [
                "name" => "preg_replace with /e modifier (code execution)",
                "severity" => "CRITICAL",
            ],
        ];

        return $this->scanPatterns(
            $this->scanLines($content),
            $path,
            $patterns,
            "Code Analysis",
        );
    }
}
