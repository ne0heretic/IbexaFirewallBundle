Update composer.json "autoload" to:
```javascript
    "autoload": {
        "psr-4": {
            "App\\": "src/",
            "": "bundles/"
        }
    },
```

Create ./bundles

Copy the bundle folder to ./bundles/Ne0Heretic/.

Copy ne0heretic_firewall.yaml.sample to ./config/routes/ne0heretic_firewall.yaml

Then update ./config/bundles.php

And update the bundles array with the new bundle

Ne0Heretic\FirewallBundle\Ne0HereticFirewallBundle::class => ['all' => true],

composer dumpautoload

# Required

RedisTagAwareAdapter.

Node:

yarn add javascript-obfuscator
yarn add chart.js


MySQL:

CREATE TABLE server_metrics (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    cpu DECIMAL(5,2) NOT NULL,
    memory DECIMAL(5,2) NOT NULL,
    redis_mem DECIMAL(5,2) NOT NULL DEFAULT 0.0000,
    apache2_mem DECIMAL(5,2) NOT NULL DEFAULT 0.0000,
    varnish_mem DECIMAL(5,2) NOT NULL DEFAULT 0.0000,
    mysql_mem DECIMAL(5,2) NOT NULL DEFAULT 0.0000,
    os_disk DECIMAL(5,2) NOT NULL DEFAULT 0.0000,
    data_disk DECIMAL(5,2) NOT NULL DEFAULT 0.0000,
    INDEX idx_timestamp (timestamp)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE http_request_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    ip VARCHAR(45) NOT NULL,
    path VARCHAR(255) NOT NULL,
    query TEXT,
    agent TEXT,
    firewallTime DECIMAL(10,6) NOT NULL DEFAULT 0.000000,
    responseTime DECIMAL(10,6) NOT NULL DEFAULT 0.000000,
    isBotAgent TINYINT(1) NOT NULL DEFAULT 0,
    isBannedBot TINYINT(1) NOT NULL DEFAULT 0,
    isChallenge TINYINT(1) NOT NULL DEFAULT 0,
    isRateLimited TINYINT(1) NOT NULL DEFAULT 0,
    INDEX idx_timestamp (timestamp),
    INDEX idx_ip (ip),
    INDEX idx_path (path)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

CREATE TABLE firewall_config (
    id INT PRIMARY KEY,
    config JSON NOT NULL
);