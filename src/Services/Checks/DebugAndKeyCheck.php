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
            if (strpos($contents, "'debug' => true") !== false) {
                $issues[] = 'Debug mode is enabled!';
            }
            if (strpos($contents, "'key' => null") !== false) {
                $issues[] = 'APP_KEY is not set!';
            }
        }
        return $issues;
    }
}
