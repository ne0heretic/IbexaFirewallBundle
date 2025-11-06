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

Requires node javascript-obfuscator:

yarn add javascript-obfuscator