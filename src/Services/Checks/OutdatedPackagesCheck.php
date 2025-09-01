<?php

namespace SecurityAnalyzer\Services\Checks;

class OutdatedPackagesCheck
{
    protected $path;

    public function __construct($path)
    {
        $this->path = $path;
    }

    public function run()
    {
        $issues = [];
        $composerLock = $this->path . '/composer.lock';
        if (file_exists($composerLock)) {
            $lockData = json_decode(file_get_contents($composerLock), true);
            foreach ($lockData['packages'] ?? [] as $package) {
                $issues[] = "Package {$package['name']} may be outdated: {$package['version']}";
            }
        }
        return $issues;
    }
}
