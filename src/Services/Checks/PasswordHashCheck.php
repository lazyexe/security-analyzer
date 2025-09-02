<?php

namespace SecurityAnalyzer\Services\Checks;

class PasswordHashCheck
{
    protected $path;
    protected $excludeDirs;

    public function __construct($path, $excludeDirs = [])
    {
        $this->path = $path;
        $this->excludeDirs = $excludeDirs;
    }

    public function run()
    {
        $issues = [];
        $configFile = $this->path . '/config/hashing.php';

        if (!file_exists($configFile)) {
            $issues[] = [
                'type' => 'Password Hash Config Missing',
                'severity' => 'high',
                'message' => 'config/hashing.php not found.',
                'file' => 'config/hashing.php',
                'line' => 0,
                'recommendation' => 'Ensure proper password hash driver (bcrypt or argon2) is configured.'
            ];
            return $issues;
        }

        $config = include $configFile;
        if (!isset($config['driver']) || !in_array($config['driver'], ['bcrypt', 'argon2'])) {
            $issues[] = [
                'type' => 'Weak Password Hash Driver',
                'severity' => 'high',
                'message' => 'Password hash driver is not secure.',
                'file' => str_replace($this->path . DIRECTORY_SEPARATOR, '', $configFile),
                'line' => 0,
                'recommendation' => 'Use bcrypt or argon2 as hashing driver.'
            ];
        }

        return $issues;
    }
}
