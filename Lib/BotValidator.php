<?php

namespace Ne0Heretic\FirewallBundle\Lib;

use Symfony\Component\Cache\Adapter\RedisTagAwareAdapter;
use Ne0Heretic\FirewallBundle\Lib\ChallengeService;

class BotValidator
{
    /** @var RedisTagAwareAdapter */
    protected $cache;
    private $challengeService;

    // Rate limiting configuration
    private const RATE_LIMIT_WINDOW = 121; // in seconds
    private const RATE_LIMIT_MAX_REQUESTS = 30;
    private const BUCKET_SIZE = 11; // Seconds per bucket
    private const BUCKET_COUNT = 11; // Buckets to cover the time window

    public function __construct(RedisTagAwareAdapter $cache, ChallengeService $challengeService = null)
    {
        $this->cache = $cache;
        $this->challengeService = $challengeService ?? null;
    }

    /**
     * Check if IP is globally banned for bot spoofing
     *
     * @param string $ip
     * @return bool
     */
    public function isBanned(string $ip): bool
    {
        $banKey = 'bot_ban_' . md5($ip);
        $banned = $this->cache->getItem($banKey);
        return $banned->isHit() && $banned->get();
    }

    /**
     * Check rate limit for the IP
     * Increments request count and returns false if limit exceeded
     *
     * @param string $ip
     * @return bool True if under limit, false if rate limited
     */
    public function checkRateLimit(string $ip): bool
    {
        $baseKey = 'rate_bucket_' . md5($ip);
        $now = time();
        $currentBucket = (int) ($now / self::BUCKET_SIZE);

        $totalRequests = 0.0;  // Float for weights
        $weight = 1.0;
        $hitCount = 0;  // Debug: number of hit buckets

        for ($i = 0; $i < self::BUCKET_COUNT; $i++) {
            $bucketIndex = $currentBucket - $i;
            $bucketKey = $baseKey . '_' . $bucketIndex;

            $bucketItem = $this->cache->getItem($bucketKey);
            if ($bucketItem->isHit()) {
                $count = $bucketItem->get();
                $totalRequests += (int) $count * $weight;
                $hitCount++;
            }
            // Decay always (for sliding effect on older slots)
            $weight -= (1.0 / self::BUCKET_COUNT);

            // Only save if hit (avoids storing nulls; set TTL anyway)
            if ($bucketItem->isHit()) {
                $bucketItem->expiresAfter(self::RATE_LIMIT_WINDOW);
                $this->cache->save($bucketItem);
            }
        }

        if ($totalRequests >= self::RATE_LIMIT_MAX_REQUESTS) {
            $this->banIpGlobally($ip);
            return false;
        }

        // Increment current bucket
        $currentBucketItem = $this->cache->getItem($baseKey . '_' . $currentBucket);
        $currentCount = $currentBucketItem->get() ?? 0;
        $currentBucketItem->set($currentCount + 1);
        $currentBucketItem->expiresAfter(self::RATE_LIMIT_WINDOW);
        $this->cache->save($currentBucketItem);

        return true;
    }

    /**
     * Validate if the IP belongs to a legitimate Googlebot
     * Uses DNS forward/reverse checks (Google's recommended method)
     * Caches result in Redis for 24 hours to avoid repeated lookups
     *
     * @param string $ip
     * @return bool
     */
    public function validateGooglebot(string $ip): bool
    {
        $cacheKey = 'googlebot_valid_' . md5($ip);
        $cached = $this->cache->getItem($cacheKey);
        if ($cached->isHit()) {
            return $cached->get();
        }

        // Perform reverse DNS lookup
        $hostname = gethostbyaddr($ip);
        if ($hostname === $ip) {
            // No reverse DNS resolution
            $cached->set(false);
            $cached->expiresAfter(86400);
            $this->cache->save($cached);
            return false;
        }

        // Check if hostname ends with .googlebot.com or .google.com
        if (substr($hostname, -12) !== '.googlebot.com' && substr($hostname, -11) !== '.google.com') {
            $cached->set(false);
            $cached->expiresAfter(86400);
            $this->cache->save($cached);
            return false;
        }

        // Perform forward DNS lookup and verify it matches the original IP
        if ($this->forwardDnsMatches($hostname, $ip)) {
            $cached->set(true);
            $cached->expiresAfter(86400);
            $this->cache->save($cached);
            return true;
        }

        $cached->set(false);
        $cached->expiresAfter(86400);
        $this->cache->save($cached);
        return false;
    }

    /**
     * Validate if the IP belongs to a legitimate Twitterbot (X)
     * Uses DNS forward/reverse checks
     * Caches result in Redis for 24 hours
     *
     * @param string $ip
     * @return bool
     */
    public function validateTwitterbot(string $ip): bool
    {
        $cacheKey = 'twitterbot_valid_' . md5($ip);
        $cached = $this->cache->getItem($cacheKey);
        if ($cached->isHit()) {
            return $cached->get();
        }

        $hostname = gethostbyaddr($ip);
        if ($hostname === $ip) {
            $cached->set(false);
            $cached->expiresAfter(86400);
            $this->cache->save($cached);
            return false;
        }

        if (substr($hostname, -11) !== '.twitter.com') {
            $cached->set(false);
            $cached->expiresAfter(86400);
            $this->cache->save($cached);
            return false;
        }

        if ($this->forwardDnsMatches($hostname, $ip)) {
            $cached->set(true);
            $cached->expiresAfter(86400);
            $this->cache->save($cached);
            return true;
        }

        $cached->set(false);
        $cached->expiresAfter(86400);
        $this->cache->save($cached);
        return false;
    }

    /**
     * Validate if the IP belongs to a legitimate Facebookbot (Facebot)
     * Uses DNS forward/reverse checks (common practice; official prefers IP list via whois AS32934)
     * Caches result in Redis for 24 hours
     *
     * @param string $ip
     * @return bool
     */
    public function validateFacebookbot(string $ip): bool
    {
        $cacheKey = 'facebookbot_valid_' . md5($ip);
        $cached = $this->cache->getItem($cacheKey);
        if ($cached->isHit()) {
            return $cached->get();
        }

        $hostname = gethostbyaddr($ip);
        if ($hostname === $ip) {
            $cached->set(false);
            $cached->expiresAfter(86400);
            $this->cache->save($cached);
            return false;
        }

        if (substr($hostname, -10) !== '.facebook.com') {
            $cached->set(false);
            $cached->expiresAfter(86400);
            $this->cache->save($cached);
            return false;
        }

        if ($this->forwardDnsMatches($hostname, $ip)) {
            $cached->set(true);
            $cached->expiresAfter(86400);
            $this->cache->save($cached);
            return true;
        }

        $cached->set(false);
        $cached->expiresAfter(86400);
        $this->cache->save($cached);
        return false;
    }

    /**
     * Validate if the IP belongs to a legitimate Bingbot
     * Uses DNS forward/reverse checks (Microsoft's recommended method)
     * Caches result in Redis for 24 hours
     *
     * @param string $ip
     * @return bool
     */
    public function validateBingbot(string $ip): bool
    {
        $cacheKey = 'bingbot_valid_' . md5($ip);
        $cached = $this->cache->getItem($cacheKey);
        if ($cached->isHit()) {
            return $cached->get();
        }

        $hostname = gethostbyaddr($ip);
        if ($hostname === $ip) {
            $cached->set(false);
            $cached->expiresAfter(86400);
            $this->cache->save($cached);
            return false;
        }

        if (substr($hostname, -15) !== '.search.msn.com') {
            $cached->set(false);
            $cached->expiresAfter(86400);
            $this->cache->save($cached);
            return false;
        }

        if ($this->forwardDnsMatches($hostname, $ip)) {
            $cached->set(true);
            $cached->expiresAfter(86400);
            $this->cache->save($cached);
            return true;
        }

        $cached->set(false);
        $cached->expiresAfter(86400);
        $this->cache->save($cached);
        return false;
    }

    /**
     * Validate if the IP belongs to a legitimate LinkedInBot
     * Uses DNS forward/reverse checks
     * Caches result in Redis for 24 hours
     *
     * @param string $ip
     * @return bool
     */
    public function validateLinkedInBot(string $ip): bool
    {
        $cacheKey = 'linkedinbot_valid_' . md5($ip);
        $cached = $this->cache->getItem($cacheKey);
        if ($cached->isHit()) {
            return $cached->get();
        }

        $hostname = gethostbyaddr($ip);
        if ($hostname === $ip) {
            $cached->set(false);
            $cached->expiresAfter(86400);
            $this->cache->save($cached);
            return false;
        }

        if (substr($hostname, -12) !== '.linkedin.com') {
            $cached->set(false);
            $cached->expiresAfter(86400);
            $this->cache->save($cached);
            return false;
        }

        if ($this->forwardDnsMatches($hostname, $ip)) {
            $cached->set(true);
            $cached->expiresAfter(86400);
            $this->cache->save($cached);
            return true;
        }

        $cached->set(false);
        $cached->expiresAfter(86400);
        $this->cache->save($cached);
        return false;
    }

    /**
     * Helper: Perform forward DNS lookup and check if original IP matches resolved IPs
     * Supports IPv4 (A) and IPv6 (AAAA) records
     *
     * @param string $hostname
     * @param string $ip
     * @return bool
     */
    private function forwardDnsMatches(string $hostname, string $ip): bool
    {
        $resolvedIps = [];

        // IPv4 A records
        $aRecords = dns_get_record($hostname, DNS_A);
        if ($aRecords) {
            foreach ($aRecords as $record) {
                $resolvedIps[] = $record['ip'];
            }
        } else {
            $forwardIpv4 = gethostbyname($hostname);
            if ($forwardIpv4 !== false && $forwardIpv4 !== $hostname) {
                $resolvedIps[] = $forwardIpv4;
            }
        }

        // IPv6 AAAA records (if IP is IPv6)
        if (filter_var($ip, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6)) {
            $aaaaRecords = dns_get_record($hostname, DNS_AAAA);
            if ($aaaaRecords) {
                foreach ($aaaaRecords as $record) {
                    $resolvedIps[] = $record['ipv6'];
                }
            }
        }

        return in_array($ip, $resolvedIps, true);
    }

    /**
     * Helper: Ban IP globally across all bot checks (1h TTL)
     */
    public function banIpGlobally(string $ip): void
    {
        $banKey = 'bot_ban_' . md5($ip);
        $banItem = $this->cache->getItem($banKey);
        $banItem->set(true);
        $banItem->expiresAfter(3600);  // 1h; adjust as needed
        $this->cache->save($banItem);
    }
}