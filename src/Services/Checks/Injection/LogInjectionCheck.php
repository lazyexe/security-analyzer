<?php
namespace SecurityAnalyzer\Checks\Injection;

use SecurityAnalyzer\Checks\BaseChecks;

class LogInjectionCheck extends BaseChecks
{
    public function check(string $path): array
    {
        $content = $this->loadFile($path);

        $patterns = [
            '/Log::info\([^)]*\$_(?:GET|POST|REQUEST)/' => [
                "name" => "Log injection via Log::info",
                "severity" => "LOW",
            ],
            '/error_log\([^)]*\$_(?:GET|POST)/' => [
                "name" => "Log injection via error_log",
                "severity" => "LOW",
            ],
        ];

        return $this->scanPatterns(
            $this->scanLines($content),
            $path,
            $patterns,
            "Log Analysis",
        );
    }
}
