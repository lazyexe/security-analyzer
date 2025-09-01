<?php

return [
    'report_path' => storage_path('security-report.json'),
    'report_html' => storage_path('security-report.html'),

    'checks' => [
        'env_file'            => true,
        'debug_and_key'       => true,
        'sensitive_files'     => true,
        'folder_permissions'  => true,
        'outdated_packages'   => false,
        'php_code_risks'      => true,
        'csrf_check'          => true,
    ],

    'exclude_dirs' => [
        'bootstrap',
        'node_modules',
        'packages',
        'tests',
        'vendor',
    ],

    'exclude_files' => [
        '*.log',
        '*.tmp',
    ],
];
