<?php
namespace SecurityAnalyzer\Checks\Injection;
use SecurityAnalyzer\Checks\BaseChecks;

class XPathInjection extends BaseChecks
{
    public function check(string $path): array
    {
        $content = $this->loadFile($path);

        $patterns = [
            '/->query\([^)]*\$/' => [
                "name" => "XPath query with user input",
                "severity" => "HIGH",
            ],
        ];

        return $this->scanPatterns(
            $this->scanLines($content),
            $path,
            $patterns,
            "XPath Analysis",
        );
    }
}
