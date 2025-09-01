<?php

namespace SecurityAnalyzer\Services\Checks;

class PhpCodeRiskCheck
{
    protected $path;
    protected $excludeDirs;
    protected $excludeFiles;

    public function __construct($path, $excludeDirs = [], $excludeFiles = [])
    {
        $this->path = $path;
        $this->excludeDirs = $excludeDirs;
        $this->excludeFiles = $excludeFiles;
    }

    public function run()
    {
        $issues = [];
        $files = $this->scanPhpFiles($this->path);

        foreach ($files as $file) {
            $content = file_get_contents($file);

            if (preg_match('/DB::raw\(|->where\(.*\$_(GET|POST|REQUEST)/i', $content)) {
                $issues[] = "Potential SQL Injection in: {$file}";
            }

            if (preg_match('/echo\s+\$_(GET|POST|REQUEST)/i', $content)) {
                $issues[] = "Potential XSS (unescaped output) in: {$file}";
            }

            if (preg_match('/include|require|include_once|require_once.*\$_/', $content)) {
                $issues[] = "Dynamic include/require detected in: {$file}";
            }
        }

        return $issues;
    }

    protected function scanPhpFiles($dir)
    {
        $rii = new \RecursiveIteratorIterator(new \RecursiveDirectoryIterator($dir));
        $files = [];
        foreach ($rii as $file) {
            if ($file->isDir()) continue;

            $pathName = $file->getPathname();

            foreach ($this->excludeDirs as $exDir) {
                if (strpos($pathName, DIRECTORY_SEPARATOR . $exDir . DIRECTORY_SEPARATOR) !== false) {
                    continue 2;
                }
            }

            foreach ($this->excludeFiles as $pattern) {
                if (fnmatch($pattern, $file->getFilename())) {
                    continue 2;
                }
            }

            if ($file->getExtension() === 'php') {
                $files[] = $pathName;
            }
        }
        return $files;
    }
}
