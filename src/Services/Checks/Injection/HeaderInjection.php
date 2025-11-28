<?php
namespace SecurityAnalyzer\Checks\Injection;
use SecurityAnalyzer\Checks\BaseChecks;

class HeaderInjection extends BaseChecks
{
    public function check(string $path): array
    {
        $content = $this->loadFile($path);

        $patterns = [
            '/header\s*\([^)]*\$_(?:GET|POST|REQUEST)/' => [
                "name" => "Header injection via header()",
                "severity" => "MEDIUM",
            ],
            '/Location:.*\$_(?:GET|POST)/' => [
                "name" => "Open redirect via Location header",
                "severity" => "MEDIUM",
            ],
        ];

        return $this->scanPatterns(
            $this->scanLines($content),
            $path,
            $patterns,
            "Header Analysis",
        );
    }
}
