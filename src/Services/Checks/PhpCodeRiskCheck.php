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
            $lines = explode("\n", $content);

            foreach ($lines as $lineNumber => $line) {
                if (preg_match('/DB::raw\(|->where\(.*\$_(GET|POST|REQUEST)/i', $line)) {
                    $issues[] = [
                        'type' => 'SQL Injection Risk',
                        'severity' => 'high',
                        'message' => 'Potential SQL Injection vulnerability detected',
                        'file' => str_replace($this->path . DIRECTORY_SEPARATOR, '', $file),
                        'line' => $lineNumber + 1,
                        'recommendation' => 'Use parameterized queries and avoid raw SQL with user input'
                    ];
                }

                if (preg_match('/echo\s+\$_(GET|POST|REQUEST)/i', $line)) {
                    $issues[] = [
                        'type' => 'XSS Risk',
                        'severity' => 'high',
                        'message' => 'Potential XSS vulnerability (unescaped output)',
                        'file' => str_replace($this->path . DIRECTORY_SEPARATOR, '', $file),
                        'line' => $lineNumber + 1,
                        'recommendation' => 'Use {{ }} in Blade templates or htmlspecialchars() to escape output'
                    ];
                }

                if (preg_match('/include|require|include_once|require_once.*\$_/', $line)) {
                    $issues[] = [
                        'type' => 'File Inclusion Risk',
                        'severity' => 'medium',
                        'message' => 'Dynamic include/require detected',
                        'file' => str_replace($this->path . DIRECTORY_SEPARATOR, '', $file),
                        'line' => $lineNumber + 1,
                        'recommendation' => 'Avoid dynamic file inclusion with user input'
                    ];
                }
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
