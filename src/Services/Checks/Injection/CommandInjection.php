<?php
namespace SecurityAnalyzer\Checks\Injection;
use SecurityAnalyzer\Checks\BaseChecks;

class CommandInjection extends BaseChecks
{
    public function check(string $path): array
    {
        $content = $this->loadFile($path);
        $lines = $this->scanLines($content);
        $findings = [];

        $dangerousFunctions = [
            "exec",
            "shell_exec",
            "system",
            "passthru",
            "proc_open",
            "popen",
            "pcntl_exec",
        ];

        foreach ($lines as $lineNum => $line) {
            foreach ($dangerousFunctions as $func) {
                if (preg_match("/{$func}\s*\([^)]*\\\$/", $line)) {
                    if (
                        !preg_match("/escapeshellarg|escapeshellcmd/", $content)
                    ) {
                        $findings[] = $this->createFinding(
                            "Command injection via {$func}()",
                            $path,
                            $lineNum + 1,
                            "CRITICAL",
                            "Command Analysis",
                        );
                    }
                }
            }
        }

        return $findings;
    }
}
