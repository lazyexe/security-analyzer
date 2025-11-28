<?php
namespace SecurityAnalyzer\Checks\Injection;
use SecurityAnalyzer\Checks\BaseChecks;

class EmailInjectionCheck extends BaseChecks
{
    public function check(string $path): array
    {
        $content = $this->loadFile($path);
        $findings = [];

        if (preg_match('/mail\s*\([^)]*\$_(?:GET|POST|REQUEST)/', $content)) {
            $findings[] = $this->createFinding(
                "Email header injection via mail()",
                $path,
                1,
                "MEDIUM",
                "Email Analysis",
            );
        }

        if (preg_match('/(From|To|Cc|Bcc):.*\$/', $content)) {
            $findings[] = $this->createFinding(
                "Unvalidated email in mail headers",
                $path,
                1,
                "MEDIUM",
                "Email Analysis",
            );
        }

        return $findings;
    }
}
