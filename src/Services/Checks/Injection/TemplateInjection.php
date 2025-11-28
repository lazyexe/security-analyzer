<?php

namespace SecurityAnalyzer\Checks\Injection;
use SecurityAnalyzer\Checks\BaseChecks;

class TemplateInjection extends BaseChecks
{
    public function check(string $path): array
    {
        $content = $this->loadFile($path);

        $patterns = [
            '/\{\{.*\$_(?:GET|POST|REQUEST).*\}\}/' => [
                "name" => "Template injection in Blade/Twig",
                "severity" => "HIGH",
            ],
            '/render\([^)]*\$_(?:GET|POST)/' => [
                "name" => "Template render with user input",
                "severity" => "HIGH",
            ],
        ];

        return $this->scanPatterns(
            $this->scanLines($content),
            $path,
            $patterns,
            "Template Analysis",
        );
    }
}
