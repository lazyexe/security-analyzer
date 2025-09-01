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
            $issues[] = 'Found .env file in project root!';
        }
        return $issues;
    }
}
