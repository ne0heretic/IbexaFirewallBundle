<?php

namespace Ne0Heretic\FirewallBundle\Lib;

use Symfony\Component\Cache\Adapter\RedisTagAwareAdapter;
use Symfony\Component\HttpFoundation\Request;

class ChallengeService
{
    /** @var RedisTagAwareAdapter */
    protected $cache;
    /** @var string */
    private string $cacheDir;

    // PoW config
    private const CHALLENGE_TTL = 300; // 5min
    private const VERIFIED_TTL = 1800; // 30min
    private const SECRET_LENGTH = 16; // Bytes for secret
    private const DUMMY_RATIO = 0.2; // 20% dummies for "break"
    private const DUMMY_CHAR = '!'; // Not in Base64 alphabet

    public function __construct(RedisTagAwareAdapter $cache, string $cacheDir = null)
    {
        $this->cache = $cache;
        $this->cacheDir = $cacheDir ?? sys_get_temp_dir(); // Fallback
    }

    /**
     * Generate broken Base64 challenge.
     */
    public function generateChallenge(): array
    {
        $secret = random_bytes(self::SECRET_LENGTH);
        $encoded = base64_encode($secret);
        $broken = $this->breakString($encoded);

        $method = 'reverse_filter_dummy';

        $cacheKey = $this->getChallengeKey($broken);
        $item = $this->cache->getItem($cacheKey);
        $item->set([
            'secret' => $secret,
            'method' => $method,
            'encoded' => $encoded
        ]);
        $item->expiresAfter(self::CHALLENGE_TTL);
        $this->cache->save($item);

        return [
            'broken' => $broken,
            'method' => $method,
            'id' => $broken
        ];
    }

    /**
     * Break Base64: Reverse + insert dummies (e.g., '=').
     */
    private function breakString(string $encoded): string
    {
        $reversed = strrev($encoded);
        $len = strlen($reversed);
        $dummies = (int) ($len * self::DUMMY_RATIO);
        $broken = $reversed;
        for ($i = 0; $i < $dummies; $i++) {
            $pos = random_int(0, $len + $i);
            $broken = substr($broken, 0, $pos) . self::DUMMY_CHAR . substr($broken, $pos);
        }
        return $broken;
    }

    /**
     * Get obfuscated JS solver script with anti-debug.
     */
    public function getObfuscatedSolverJs(string $broken, string $method): string
    {
        $template = $this->getJsTemplate($broken, $method);
        return $this->simpleObfuscate($template);
    }

    /**
     * Get JS template with fix logic (obfuscator mangles this).
     */
    public function getJsTemplate(string $broken, string $method): string
    {
        $fixLogic = match ($method) {
            'reverse_filter_dummy' => 'const fixed = broken.split("").reverse().join("").replace(/!/g, "");',
            default => 'const fixed = broken;'
        };

        return <<<JS
    (function() {
        const start = performance.now();
        console.log('chk');
        const end = performance.now();
        if (end - start > 15) { return; }
        // TODO: language, and webgl checks should fall back to captcha verification
        if (navigator.plugins.length < 5) { return; }
        //if (!navigator.languages || navigator.languages.length <= 1) { return; } // Language check
        if (navigator.webdriver) { return; } // New: Webdriver flag

        // Canvas/WebGL renderer check
        const canvas = document.createElement('canvas');
        const gl = canvas.getContext('webgl');
        if (gl) {
            const debugInfo = gl.getExtension('WEBGL_debug_renderer_info');
            if (debugInfo) {
                const renderer = gl.getParameter(debugInfo.UNMASKED_RENDERER_WEBGL);
                if (renderer && (renderer.includes('SwiftShader') || renderer.includes('Mesa') || renderer.includes('OffScreen'))) {
                    return;
                }
            }
        }

        const broken = '{$broken}';

        {$fixLogic}
        try {
            const rawToken = atob(fixed);
            if (rawToken.length === 16) {
                const safeToken = btoa(rawToken); // Re-base64 for safe transmission
                localStorage.setItem('challengeToken', safeToken);
                localStorage.setItem('challengeId', broken);
                document.cookie = `challengeToken=\${safeToken}; path=/; max-age=1800; SameSite=Strict`;
                document.cookie = `challengeId=\${broken}; path=/; max-age=1800; SameSite=Strict`;
                console.log('Fixed and decoded');
                window.location.reload();
            } else {
                console.error('Fix failed: invalid length');
            }
        } catch (e) {
            console.error('Fix failed: ' + e.message);
        }

        const origFetch = window.fetch;
        window.fetch = function(...args) {
            const safeToken = localStorage.getItem('challengeToken');
            const id = localStorage.getItem('challengeId');
            if (safeToken && id && args[1]) {
                args[1].headers = { ...args[1].headers, 'X-Challenge-Token': safeToken, 'X-Challenge-Id': id };
            }
            return origFetch.apply(this, args);
        };
    })();
    JS;
    }

    /**
     * Obfuscate using javascript-obfuscator (Node.js tool).
     * Assumes 'npx javascript-obfuscator' available; adjust path for local install.
     */
    private function simpleObfuscate(string $js): string
    {
        $baseTemp = rtrim($this->cacheDir, '/') . '/js_obf_' . uniqid();
        $tempIn = $baseTemp . '_in.js';
        $tempOut = $baseTemp . '_out.js';
        file_put_contents($tempIn, $js);

        $options = [
            '--compact true',
            '--string-array true',
            '--string-array-threshold 0.75',
            '--control-flow-flattening true',
            '--control-flow-flattening-threshold 0.75',
            '--dead-code-injection true',
            '--dead-code-injection-threshold 0.4',
            '--transform-object-keys false',
            "--output {$tempOut}",
            $tempIn
        ];
        $cmd = 'npx javascript-obfuscator ' . implode(' ', $options);

        $output = shell_exec($cmd . ' 2>&1');

        $obfuscated = '';
        if (file_exists($tempOut)) {
            $obfuscated = file_get_contents($tempOut);
            unlink($tempOut);
        }
        unlink($tempIn);

        if (empty($obfuscated)) {
            error_log("Obfuscation failed: {$output}. Falling back to plain JS.");
            return $js;
        }
        return $obfuscated;
    }

    /**
     * Verify: Decode token, match stored secret.
     */
    public function verifyChallenge(string $challengeId, string $token, string $ip): bool
    {
        $cacheKey = $this->getChallengeKey($challengeId);
        $item = $this->cache->getItem($cacheKey);
        if (!$item->isHit()) {
            error_log("Verify fail: No cache hit for ID {$challengeId}");
            return false;
        }

        $data = $item->get();
        $expectedSecret = $data['secret'];

        // Decode submitted (base64 to raw)
        $submittedSecret = base64_decode($token, true); // Strict mode
        if ($submittedSecret === false) {
            error_log("Verify fail: Invalid base64 token for ID {$challengeId}");
            return false;
        }

        if (strlen($submittedSecret) !== self::SECRET_LENGTH || $submittedSecret !== $expectedSecret) {
            error_log("Verify fail: Mismatch for ID {$challengeId}. Expected: " . bin2hex($expectedSecret) . " Submitted: " . bin2hex($submittedSecret));
            return false;
        }

        $this->setVerified($ip);
        return true;
    }

    /**
     * Check if IP is verified (skip challenges).
     */
    public function isVerified(string $ip): bool
    {
        $key = 'challenge_verified_' . md5($ip);
        $item = $this->cache->getItem($key);
        return $item->isHit() && $item->get();
    }

    /**
     * Set verified flag.
     */
    private function setVerified(string $ip): void
    {
        $key = 'challenge_verified_' . md5($ip);
        $item = $this->cache->getItem($key);
        $item->set(true);
        $item->expiresAfter(self::VERIFIED_TTL);
        $this->cache->save($item);
    }

    /**
     * Mark challenge pending for IP.
     */
    public function setPending(string $ip, string $challengeId): void
    {
        $key = 'challenge_pending_' . md5($ip);
        $item = $this->cache->getItem($key);
        $item->set($challengeId);
        $item->expiresAfter(self::CHALLENGE_TTL);
        $this->cache->save($item);
    }

    /**
     * Get pending challenge ID for IP.
     */
    public function getPending(string $ip): ?string
    {
        $key = 'challenge_pending_' . md5($ip);
        $item = $this->cache->getItem($key);
        return $item->isHit() ? $item->get() : null;
    }

    /**
     * Clear pending.
     */
    public function clearPending(string $ip): void
    {
        $key = 'challenge_pending_' . md5($ip);
        $this->cache->deleteItem($key);
    }

    private function getChallengeKey(string $id): string
    {
        return 'challenge_secret_' . $id;
    }

    private function getTargetKey(string $id): string
    {
        return 'challenge_target_' . $id;
    }
}