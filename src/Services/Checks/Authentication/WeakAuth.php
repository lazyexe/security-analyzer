<?php

namespace SecurityAnalyzer\Checks\Authentication;
use SecurityAnalyzer\Checks\BaseChecks;

class WeakAuthenticationCheck extends BaseChecks
{
    public function check(string $path): array
    {
        $content = file_get_contents($path);

        $patterns = [
            '/if\s*\(\s*\$.*==.*[\'"]admin[\'"]\s*\)/' =>
                "Hardcoded admin check",
            "/if\s*\(\s*true\s*\).*auth/" => "Always-true authentication",
            '/if\s*\(\s*!?empty\(\$password\)\s*\).*login/' =>
                "Weak password validation",
        ];

        return $this->scanPatterns(
            $this->scanLines($content),
            $path,
            $patterns,
            "Weak Authentication",
        );
    }
}
