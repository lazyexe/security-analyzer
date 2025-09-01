<?php

namespace SecurityAnalyzer\Commands;

use Illuminate\Console\Command;
use SecurityAnalyzer\Services\SecurityScanner;

class ScanSecurity extends Command
{
    protected $signature = 'security:scan 
                            {--path= : Path to scan (default: current project)} 
                            {--output= : Output format (console|json|html|all)} 
                            {--no-report : Skip saving report files}';
    protected $description = 'Scan Laravel project for security issues';

    public function handle()
    {
        $this->info('🔒 Laravel Security Analyzer');
        $this->info('================================');
        
        $path = $this->option('path') ?: base_path();
        $output = $this->option('output') ?: 'console';
        $noReport = $this->option('no-report');
        
        $this->line("📁 Scanning path: {$path}");
        $this->newLine();
        
        // Show progress
        $this->info('🔍 Running security checks...');
        $progressBar = $this->output->createProgressBar(7);
        $progressBar->start();
        
        $scanner = new SecurityScanner($path);
        $report = $scanner->scan();
        
        $progressBar->finish();
        $this->newLine(2);
        
        // Display results
        $this->displayResults($report);
        
        // Save reports if not disabled
        if (!$noReport) {
            $this->saveReports($report, $output);
        }
        
        return $this->getExitCode($report);
    }
    
    private function displayResults($report)
    {
        $issueCount = count($report);
        
        if ($issueCount === 0) {
            $this->info('✅ No security issues found! Your Laravel project looks secure.');
            return;
        }
        
        $this->warn("⚠️  Found {$issueCount} security issue(s):");
        $this->newLine();
        
        // Debug: Check the structure of the report
        foreach ($report as $index => $item) {
            if (is_string($item)) {
                $this->error("Found string at index {$index}: {$item}");
            } elseif (!is_array($item)) {
                $this->error("Found non-array item at index {$index}: " . gettype($item));
            } elseif (!isset($item['type'])) {
                $this->error("Found array without 'type' key at index {$index}: " . json_encode($item));
            }
        }
        
        $groupedIssues = $this->groupIssuesByType($report);
        
        foreach ($groupedIssues as $type => $issues) {
            $this->line("<fg=red>🚨 {$type} ({" . count($issues) . " issue(s))</>");
            
            foreach ($issues as $issue) {
                if (is_array($issue) && isset($issue['message'])) {
                    $this->line("   • {$issue['message']}");
                    if (isset($issue['file'])) {
                        $this->line("     📄 File: {$issue['file']}");
                    }
                    if (isset($issue['line'])) {
                        $this->line("     📍 Line: {$issue['line']}");
                    }
                    if (isset($issue['recommendation'])) {
                        $this->line("     💡 Fix: {$issue['recommendation']}");
                    }
                } else {
                    $this->error("Invalid issue format: " . json_encode($issue));
                }
                $this->newLine();
            }
        }
    }
    
    private function groupIssuesByType($report)
    {
        $grouped = [];
        
        foreach ($report as $issue) {
            $type = $issue['type'] ?? 'Unknown';
            if (!isset($grouped[$type])) {
                $grouped[$type] = [];
            }
            $grouped[$type][] = $issue;
        }
        
        return $grouped;
    }
    
    private function saveReports($report, $outputFormat)
    {
        $this->info('💾 Saving reports...');
        
        $jsonPath = config('security-analyzer.report_path');
        $htmlPath = config('security-analyzer.report_html');
        
        if (in_array($outputFormat, ['json', 'all'])) {
            file_put_contents($jsonPath, json_encode($report, JSON_PRETTY_PRINT));
            $this->line("📄 JSON report saved: {$jsonPath}");
        }
        
        if (in_array($outputFormat, ['html', 'all'])) {
            $htmlContent = $this->generateHtmlReport($report);
            file_put_contents($htmlPath, $htmlContent);
            $this->line("🌐 HTML report saved: {$htmlPath}");
        }
        
        if ($outputFormat === 'console' || $outputFormat === 'all') {
            // Always save JSON for console output as backup
            file_put_contents($jsonPath, json_encode($report, JSON_PRETTY_PRINT));
            $this->line("📄 Backup JSON report saved: {$jsonPath}");
        }
    }
    
    private function generateHtmlReport($report)
    {
        $issueCount = count($report);
        $timestamp = date('Y-m-d H:i:s');
        
        $html = "<!DOCTYPE html>
<html>
<head>
    <title>Security Analysis Report</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .header { background: #f8f9fa; padding: 20px; border-radius: 5px; }
        .issue { background: #fff3cd; border: 1px solid #ffeaa7; padding: 15px; margin: 10px 0; border-radius: 5px; }
        .high { border-left: 5px solid #dc3545; }
        .medium { border-left: 5px solid #ffc107; }
        .low { border-left: 5px solid #28a745; }
        .summary { background: #d4edda; padding: 15px; border-radius: 5px; margin: 20px 0; }
    </style>
</head>
<body>
    <div class='header'>
        <h1>🔒 Laravel Security Analysis Report</h1>
        <p><strong>Generated:</strong> {$timestamp}</p>
        <p><strong>Issues Found:</strong> {$issueCount}</p>
    </div>";
        
        if ($issueCount === 0) {
            $html .= "<div class='summary'><h2>✅ No Issues Found</h2><p>Your Laravel project appears to be secure!</p></div>";
        } else {
            $groupedIssues = $this->groupIssuesByType($report);
            
            foreach ($groupedIssues as $type => $issues) {
                $html .= "<h2>🚨 {$type} (" . count($issues) . " issue(s))</h2>";
                
                foreach ($issues as $issue) {
                    $severity = $issue['severity'] ?? 'medium';
                    $html .= "<div class='issue {$severity}'>";
                    $html .= "<h3>{$issue['message']}</h3>";
                    
                    if (isset($issue['file'])) {
                        $html .= "<p><strong>File:</strong> {$issue['file']}</p>";
                    }
                    
                    if (isset($issue['line'])) {
                        $html .= "<p><strong>Line:</strong> {$issue['line']}</p>";
                    }
                    
                    if (isset($issue['recommendation'])) {
                        $html .= "<p><strong>Recommendation:</strong> {$issue['recommendation']}</p>";
                    }
                    
                    $html .= "</div>";
                }
            }
        }
        
        $html .= "</body></html>";
        
        return $html;
    }
    
    private function getExitCode($report)
    {
        return count($report) > 0 ? 1 : 0;
    }
}
