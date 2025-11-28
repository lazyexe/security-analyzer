<?php
namespace SecurityAnalyzer\Checks\Injection;
use SecurityAnalyzer\Checks\BaseChecks;

class CookieInjectionCheck extends BaseChecks
{
    public function check(string $path): array
    {
        $content = $this->loadFile($path);
        $findings = [];

        if (preg_match('/setcookie\s*\([^)]*\$_(?:GET|POST)/', $content)) {
            $findings[] = $this->createFinding(
                "Cookie value set from user input",
                $path,
                1,
                "MEDIUM",
                "Cookie Analysis",
            );
        }

        if (
            preg_match(
                "/setcookie\([^,]+,[^,]+(?!.*secure)(?!.*httponly)\)/",
                $content,
            )
        ) {
            $findings[] = $this->createFinding(
                "Cookie without Secure/HttpOnly flags",
                $path,
                1,
                "MEDIUM",
                "Cookie Analysis",
            );
        }

        return $findings;
    }
}
