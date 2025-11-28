<?php

return [
    "report_path" => storage_path("security-report.json"),
    "report_html" => storage_path("security-report.html"),

    "checks" => [
        "env_file" => true,
        "debug_and_key" => true,
        "sensitive_files" => true,
        "folder_permissions" => true,
        "outdated_packages" => false,
        "php_code_risks" => true,
        "csrf_check" => true,
        "force_https" => true,
        "cors_check" => true,
        "route_middleware" => true,
        "api_rate_limit" => true,
        "global_throttle" => true,
        "password_hash" => true,
        "admin_panel" => true,
        "storage_symlink" => true,
        "directory_index" => true,
        "backup_file" => true,
    ],

    "exclude_dirs" => [
        "bootstrap",
        "node_modules",
        "packages",
        "tests",
        "vendor",
    ],

    "exclude_files" => ["*.log", "*.tmp"],

    // load config added

    "scoring" => [
        "enabled" => true,
        "cvss_version" => "3.1",
        "include_temporal" => true,
        "include_environmental" => false,
    ],

    "severity_thresholds" => [
        "critical" => 9.0,
        "high" => 7.0,
        "medium" => 4.0,
        "low" => 0.1,
    ],

    "data_flow" => [
        "enabled" => true,
        "max_depth" => 10,
        "track_taint" => true,
    ],

    "ast_parsing" => [
        "enabled" => true,
        "parse_vendor" => false,
    ],

    "external_services" => [
        "nvd_api" => true,
        "github_advisories" => true,
        "exploit_db" => false,
    ],

    "compliance" => [
        "owasp_top_10" => true,
        "pci_dss" => false,
        "gdpr" => false,
    ],

    "resources_thirdparty" => [
        "cvedata" => "https://services.nvd.nist.gov/rest/json/cves/2.0",
        "advisorygithub" => "https://api.github.com/advisories",
        "dblist" => "https://www.exploit-db.com/search",
        "catalog" =>
            "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        "metax" => "https://www.rapid7.com/db/search",
    ],
];
