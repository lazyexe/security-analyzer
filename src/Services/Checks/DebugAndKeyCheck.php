<?php

namespace SecurityAnalyzer\Services\Checks;

class DebugAndKeyCheck
{
    protected $path;

    public function __construct($path)
    {
        $this->path = $path;
    }

    public function run()
    {
        $issues = [];
        $appConfig = $this->path . '/config/app.php';
        if (file_exists($appConfig)) {
            $contents = file_get_contents($appConfig);
            $lines = explode("\n", $contents);
            
            foreach ($lines as $lineNumber => $line) {
                if (strpos($line, "'debug' => true") !== false) {
                    $issues[] = [
                        'type' => 'Debug Mode Enabled',
                        'severity' => 'high',
                        'message' => 'Debug mode is enabled in production',
                        'file' => 'config/app.php',
                        'line' => $lineNumber + 1,
                        'recommendation' => 'Set APP_DEBUG=false in production environment'
                    ];
                }
                
                if (strpos($line, "'key' => null") !== false) {
                    $issues[] = [
                        'type' => 'Missing App Key',
                        'severity' => 'critical',
                        'message' => 'Application key is not set',
                        'file' => 'config/app.php',
                        'line' => $lineNumber + 1,
                        'recommendation' => 'Run php artisan key:generate to set APP_KEY'
                    ];
                }
            }
        }
        return $issues;
    }
}
