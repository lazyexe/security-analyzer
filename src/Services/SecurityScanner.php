<?php

namespace SecurityAnalyzer\Services;

use SecurityAnalyzer\Services\Checks\EnvFileCheck;
use SecurityAnalyzer\Services\Checks\DebugAndKeyCheck;
use SecurityAnalyzer\Services\Checks\SensitiveFilesCheck;
use SecurityAnalyzer\Services\Checks\FolderPermissionsCheck;
use SecurityAnalyzer\Services\Checks\OutdatedPackagesCheck;
use SecurityAnalyzer\Services\Checks\PhpCodeRiskCheck;
use SecurityAnalyzer\Services\Checks\CsrfCheck;
use SecurityAnalyzer\Services\Checks\ForceHttpsCheck;
use SecurityAnalyzer\Services\Checks\CorsCheck;
use SecurityAnalyzer\Services\Checks\RouteMiddlewareCheck;
use SecurityAnalyzer\Services\Checks\ApiRateLimitingCheck;
use SecurityAnalyzer\Services\Checks\GlobalThrottleCheck;
use SecurityAnalyzer\Services\Checks\PasswordHashCheck;
use SecurityAnalyzer\Services\Checks\AdminPanelExposureCheck;
use SecurityAnalyzer\Services\Checks\StorageSymlinkCheck;
use SecurityAnalyzer\Services\Checks\DirectoryIndexCheck;
use SecurityAnalyzer\Services\Checks\BackupFileCheck;


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
		
		if ($config['checks']['force_https']) {
			$checks[] = new ForceHttpsCheck($this->projectPath, $config['exclude_dirs']);
		}

		if ($config['checks']['cors_check']) {
			$checks[] = new CorsCheck($this->projectPath, $config['exclude_dirs']);
		}
		
		if ($config['checks']['route_middleware']) {
			$checks[] = new RouteMiddlewareCheck($this->projectPath, $config['exclude_dirs']);
		}
		
		if ($config['checks']['api_rate_limit']) {
			$checks[] = new ApiRateLimitingCheck($this->projectPath, $config['exclude_dirs']);
		}
		
		if ($config['checks']['global_throttle']) {
			$checks[] = new GlobalThrottleCheck($this->projectPath, $config['exclude_dirs']);
		}
		
		if ($config['checks']['password_hash']) {
			$checks[] = new PasswordHashCheck($this->projectPath, $config['exclude_dirs']);
		}
		
		if ($config['checks']['admin_panel']) {
			$checks[] = new AdminPanelExposureCheck($this->projectPath, $config['exclude_dirs']);
		}
		
		if ($config['checks']['storage_symlink']) {
			$checks[] = new StorageSymlinkCheck($this->projectPath, $config['exclude_dirs']);
		}
		
		if ($config['checks']['directory_index']) {
			$checks[] = new DirectoryIndexCheck($this->projectPath, $config['exclude_dirs']);
		}
		
		if ($config['checks']['backup_file']) {
			$checks[] = new BackupFileCheck($this->projectPath, $config['exclude_dirs']);
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
