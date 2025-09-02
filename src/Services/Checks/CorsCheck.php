<?php

namespace SecurityAnalyzer\Services\Checks;

class CorsCheck
{
    protected $path;

    public function __construct($path)
    {
        $this->path = $path;
    }

    public function run()
    {
        $issues = [];
        $configFile = $this->path . '/config/cors.php';

        if (!file_exists($configFile)) {
            $issues[] = [
                'type' => 'CORS Config Missing',
                'severity' => 'high',
                'message' => 'CORS configuration file not found.',
                'file' => 'config/cors.php',
                'line' => 0,
                'recommendation' => 'Create config/cors.php using Laravel\'s default CORS configuration.'
            ];
            return $issues;
        }

        $config = include $configFile;

        if (isset($config['paths']) && isset($config['allowed_origins'])) {
            if (in_array('*', $config['allowed_origins'])) {
                $issues[] = [
                    'type' => 'Insecure CORS Policy',
                    'severity' => 'high',
                    'message' => 'CORS allowed_origins is set to wildcard (*), which is insecure.',
                    'file' => str_replace($this->path . DIRECTORY_SEPARATOR, '', $configFile),
                    'line' => 0,
                    'recommendation' => 'Replace "*" with specific allowed origins to restrict cross-origin requests.'
                ];
            }
        }

        return $issues;
    }
}
