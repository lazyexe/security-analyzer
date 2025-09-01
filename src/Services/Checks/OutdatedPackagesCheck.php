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
                $issues[] = [
                    'type' => 'Outdated Package',
                    'severity' => 'low',
                    'message' => 'Package may be outdated',
                    'file' => 'composer.lock',
                    'line' => 1,
                    'recommendation' => "Update package {$package['name']} from version {$package['version']}"
                ];
            }
        }
        return $issues;
    }
}
