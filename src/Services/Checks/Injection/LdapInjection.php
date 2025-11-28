<?php
namespace SecurityAnalyzer\Checks\Injection;
use SecurityAnalyzer\Checks\BaseChecks;

class LdapInjection extends BaseChecks
{
    public function check(string $path): array
    {
        $content = $this->loadFile($path);

        $patterns = [
            '/ldap_search\([^)]*\$(?!.*ldap_escape)/' => [
                "name" => "LDAP search without escaping",
                "severity" => "HIGH",
            ],
            '/ldap_bind\([^)]*\$/' => [
                "name" => "LDAP bind with user input",
                "severity" => "HIGH",
            ],
        ];

        return $this->scanPatterns(
            $this->scanLines($content),
            $path,
            $patterns,
            "LDAP Analysis",
        );
    }
}
