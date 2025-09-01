<?php

namespace SecurityAnalyzer\Commands;

use Illuminate\Console\Command;
use SecurityAnalyzer\Services\SecurityScanner;

class ScanSecurity extends Command
{
    protected $signature = 'security:scan {--path= : Path to scan}';
    protected $description = 'Scan Laravel project for security issues';

    public function handle()
    {
        $path = $this->option('path') ?: base_path();
        $scanner = new SecurityScanner($path);
        $report = $scanner->scan();

        file_put_contents(config('security-analyzer.report_path'), json_encode($report, JSON_PRETTY_PRINT));
        file_put_contents(config('security-analyzer.report_html'), '<pre>' . json_encode($report, JSON_PRETTY_PRINT) . '</pre>');

        $this->info('Scan completed. Found ' . count($report) . ' issues.');
    }
}
