<?php
namespace SecurityAnalyzer\Checks\Injection;
use SecurityAnalyzer\Checks\BaseChecks;

class XmlInjection extends BaseChecks
{
    public function check(string $path): array
    {
        $content = $this->loadFile($path);
        $lines = $this->scanLines($content);
        $findings = [];

        $patterns = [
            '/simplexml_load_string\([^)]*\$(?!.*LIBXML_NOENT)/' => [
                "name" => "XXE via simplexml_load_string",
                "severity" => "HIGH",
            ],
            '/DOMDocument.*loadXML\([^)]*\$/' => [
                "name" => "XXE via DOMDocument::loadXML",
                "severity" => "HIGH",
            ],
            '/xml_parse\([^)]*\$/' => [
                "name" => "XXE via xml_parse",
                "severity" => "HIGH",
            ],
        ];

        if (!preg_match("/libxml_disable_entity_loader\(true\)/", $content)) {
            $findings[] = $this->createFinding(
                "External entity loader not disabled",
                $path,
                1,
                "HIGH",
                "XML Security",
            );
        }

        return array_merge(
            $findings,
            $this->scanPatterns($lines, $path, $patterns),
        );
    }
}
