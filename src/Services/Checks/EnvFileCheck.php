<?php

namespace SecurityAnalyzer\Services\Checks;

class EnvFileCheck
{
    protected $path;

    public function __construct($path)
    {
        $this->path = $path;
    }

    public function run()
    {
        $issues = [];
        if (file_exists($this->path . '/.env')) {
            $issues[] = [
                'type' => 'Environment File Exposure',
                'severity' => 'critical',
                'message' => 'Environment file found in project root',
                'file' => '.env',
                'line' => 1,
                'recommendation' => 'Ensure .env file is not accessible via web and is properly protected'
            ];
        }
        return $issues;
    }
}
