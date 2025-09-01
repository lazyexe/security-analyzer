<?php

namespace SecurityAnalyzer\Services;

use SecurityAnalyzer\Services\Checks\EnvFileCheck;
use SecurityAnalyzer\Services\Checks\DebugAndKeyCheck;
use SecurityAnalyzer\Services\Checks\SensitiveFilesCheck;
use SecurityAnalyzer\Services\Checks\FolderPermissionsCheck;
use SecurityAnalyzer\Services\Checks\OutdatedPackagesCheck;
use SecurityAnalyzer\Services\Checks\PhpCodeRiskCheck;
use SecurityAnalyzer\Services\Checks\CsrfCheck;

class SecurityScanner
{
    protected $projectPath;
    protected $issues = [];

    public function __construct($path)
    {
        $this->projectPath = realpath($path);
    }

    public function scan()
    {
        $config = config('security-analyzer');

        $checks = [];

        if ($config['checks']['env_file']) {
            $checks[] = new EnvFileCheck($this->projectPath);
        }
        if ($config['checks']['debug_and_key']) {
            $checks[] = new DebugAndKeyCheck($this->projectPath);
        }
        if ($config['checks']['sensitive_files']) {
            $checks[] = new SensitiveFilesCheck($this->projectPath);
        }
        if ($config['checks']['folder_permissions']) {
            $checks[] = new FolderPermissionsCheck($this->projectPath);
        }
        if ($config['checks']['outdated_packages']) {
            $checks[] = new OutdatedPackagesCheck($this->projectPath);
        }
        if ($config['checks']['php_code_risks']) {
            $checks[] = new PhpCodeRiskCheck($this->projectPath, $config['exclude_dirs'], $config['exclude_files']);
        }
        if ($config['checks']['csrf_check']) {
            $checks[] = new CsrfCheck($this->projectPath, $config['exclude_dirs']);
        }

        foreach ($checks as $check) {
            $checkResults = $check->run();
            
            // Ensure all results are properly formatted
            foreach ($checkResults as $result) {
                if (is_string($result)) {
                    // Convert old string format to new array format
                    $this->issues[] = [
                        'type' => 'Legacy Check',
                        'severity' => 'medium',
                        'message' => $result,
                        'file' => 'unknown',
                        'line' => 1,
                        'recommendation' => 'Please review this issue manually'
                    ];
                } else {
                    $this->issues[] = $result;
                }
            }
        }

        return $this->issues;
    }
}
