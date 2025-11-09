<?php

namespace Ne0Heretic\FirewallBundle\EventListener;

use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Ne0Heretic\FirewallBundle\Lib\BotValidator;
use Symfony\Component\Cache\Adapter\RedisTagAwareAdapter;
use Symfony\Component\HttpFoundation\Request;
use Ne0Heretic\FirewallBundle\Lib\ChallengeService;
use Ne0Heretic\FirewallBundle\Lib\ConfigService;

class KernelListener
{
    /** @var BotValidator */
    protected $botValidator;
    /** @var RedisTagAwareAdapter */
    protected $cache;
    // Per request vars
    public static ?float $startTime = null;
    public static ?string $clientIp = null;
    public static float $firewallTime = 0.0;
    public static bool $checkRateLimit = false;
    public static bool $isBotAgent = false;
    public static bool $isBannedBot = false;
    public static bool $isChallenge = false;
    public static bool $isRateLimited = false;
    /** @var ChallengeService */
    protected $challengeService;
    /** @var ConfigService */
    protected $configService;

    private const BOT_PATTERNS = [
        'google' => ['uas' => ['Googlebot'], 'method' => 'validateGooglebot', 'enabled_key' => 'google_enabled'],
        'twitter' => ['uas' => ['Twitterbot'], 'method' => 'validateTwitterbot', 'enabled_key' => 'twitter_enabled'],
        'facebook' => ['uas' => ['facebookexternalhit', 'Facebot'], 'method' => 'validateFacebookbot', 'enabled_key' => 'facebook_enabled'],
        'bing' => ['uas' => ['bingbot', 'BingPreview'], 'method' => 'validateBingbot', 'enabled_key' => 'bing_enabled'],
        'linkedin' => ['uas' => ['LinkedInBot'], 'method' => 'validateLinkedInBot', 'enabled_key' => 'linkedin_enabled'],
    ];

    public function __construct(
        RedisTagAwareAdapter $cache,
        string $cacheDir,
        ConfigService $configService
    ) {
        self::$startTime = microtime(true);
        $this->cache = $cache;
        $this->configService = $configService;
        $this->challengeService = new ChallengeService($cache, $cacheDir, $configService);
        $this->botValidator = new BotValidator($cache, $configService);
        $request = Request::createFromGlobals();
        // Get the request IP (this uses Symfony's built-in logic, which respects trusted_proxies if configured)
        $ip = $request->getClientIp();

        // Get the forwarded IP (manual extraction if you need the raw X-Forwarded-For value or custom handling)
        $forwardedFor = $request->headers->get('X-Forwarded-For');
        $forwardedIp = null;
        if ($forwardedFor) {
            // X-Forwarded-For can contain multiple IPs (client, proxies); take the leftmost (original client)
            $ipList = explode(',', $forwardedFor);
            $forwardedIp = trim($ipList[0]);

            // Optional: Validate IP format (basic check)
            if (!filter_var($forwardedIp, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4 | FILTER_FLAG_IPV6)) {
                $forwardedIp = null; // Fallback to $ip if invalid
            }
        }

        // Use forwarded IP if available and valid, else fallback to direct client IP
        self::$clientIp = $forwardedIp ?: $ip;
        self::$firewallTime += microtime(true) - self::$startTime;
    }

    /**
     * @param RequestEvent $event
     * @return void
     */
    public function onKernelRequest(RequestEvent $event)
    {
        if (!$event->isMasterRequest()) {
            return;
        }
        $blockStartTime = microtime(true);
        $request = $event->getRequest();
        $userAgent = $request->headers->get('User-Agent') ?? '';
        $path = $request->getPathInfo();

        $config = $this->configService->getConfig();

        // Early challenge verification: Headers or cookies
        $token = $request->headers->get('X-Challenge-Token') ?: ($_COOKIE['challengeToken'] ?? null);
        $challengeId = $request->headers->get('X-Challenge-Id') ?: ($_COOKIE['challengeId'] ?? null);
        if ($token && $challengeId && $this->challengeService->verifyChallenge($challengeId, $token, self::$clientIp)) {
            self::$checkRateLimit = true;
            self::$firewallTime += microtime(true) - $blockStartTime;
            return;
        }
        // Global ban check
        else if ($this->botValidator->isBanned(self::$clientIp)) {
            self::$isBotAgent = true;
            self::$isBannedBot = true;
            error_log("Globally banned bot IP: " . self::$clientIp);
            $response = new Response('Unauthorized bot access', 403);
            $response->setPrivate();
            $response->setSharedMaxAge(0);
            $event->setResponse($response);
            self::$firewallTime += microtime(true) - $blockStartTime;
            return;
        }
        // Validate known bots
        $botMatched = false;
        foreach (self::BOT_PATTERNS as $botInfo) {
            $uaMatch = false;
            foreach ($botInfo['uas'] as $ua) {
                if (stripos($userAgent, $ua) !== false) {
                    $uaMatch = true;
                    break;
                }
            }
            if ($uaMatch) {
                self::$isBotAgent = true;
                $enabled = $config['bots'][$botInfo['enabled_key']];
                if ($enabled) {
                    if (!$this->botValidator->{$botInfo['method']}(self::$clientIp)) {
                        self::$isBannedBot = true;
                        error_log("Fake bot detected from IP: " . self::$clientIp . " with UA: $userAgent");
                        $this->botValidator->banIpGlobally(self::$clientIp);
                        $response = new Response('Unauthorized bot access', 403);
                        $response->setPrivate();
                        $response->setSharedMaxAge(0);
                        $event->setResponse($response);
                        self::$firewallTime += microtime(true) - $blockStartTime;
                        return;
                    }
                }
                $botMatched = true;
                break;
            }
        }

        if (!$botMatched) {
            self::$checkRateLimit = true;
            // Exempt paths
            $exemptPaths = $config['exemptions']['paths'] ?? [];
            $exempt = false;
            foreach ($exemptPaths as $pat) {
                if (fnmatch($pat, $path)) {
                    $exempt = true;
                    break;
                }
            }
            if (!$exempt && $config['challenge']['enabled_for_non_bots']) {
                self::$isChallenge = true;
                // Trigger challenge: Generate and short-circuit
                $challenge = $this->challengeService->generateChallenge();
                $this->challengeService->setPending(self::$clientIp, $challenge['id']);
                $js = $this->challengeService->getObfuscatedSolverJs($challenge['broken'], $challenge['method']);

                // Generate minimal challenge HTML
                $html = $this->getMinimalChallengeHtml($js, $request); // Inject broken as data-attr if needed

                $response = new Response($html, 200, [
                    'Content-Type' => 'text/html; charset=UTF-8',
                    'Cache-Control' => 'no-cache, no-store, must-revalidate',
                ]);
                $response->setPrivate();
                $response->setSharedMaxAge(0);
                $event->setResponse($response);
                error_log("Short-circuit challenge response for IP: " . self::$clientIp);
            }
        }
        self::$firewallTime += microtime(true) - $blockStartTime;
    }

    /**
     * Helper to generate minimal HTML with JS injection.
     * Customize: Embed your site's head/body or redirect to challenge route.
     */
    private function getMinimalChallengeHtml(string $js, Request $request): string
    {
        return <<<HTML
<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Verifying...</title>
<meta http-equiv="refresh" content="5"> <!-- Fallback if JS fails -->
</head>
<body>
<p>One moment while we verify your browser...</p>
<script>{$js}</script>
</body>
</html>
HTML;
    }

    /**
     * @param ResponseEvent $event
     * @return void
     */
    public function onKernelResponse(ResponseEvent $event)
    {
        $blockStartTime = microtime(true);
        $responseTime = microtime(true) - self::$startTime - self::$firewallTime;
        $config = $this->configService->getConfig();
        // Rate limiting check: Block if exceeded
        // Counting only requests that takes at least 0.1 seconds
        // Or requests that are not 2xx
        $responseCode = (int)($event->getResponse()->getStatusCode()/100);
        if ($event->isMasterRequest() && $config['enable_rate_limiting'] && self::$checkRateLimit && ($responseCode !== 2 || $responseTime > 0.1 || self::$isChallenge) && !$this->botValidator->checkRateLimit(self::$clientIp)) {
            self::$isRateLimited = true;
            error_log("Rate limit exceeded for IP: $clientIp");
            $response = new Response('Too Many Requests', 429);
            $response->setPrivate();
            $response->setSharedMaxAge(0);
            $event->setResponse($response);
        }
        $request = $event->getRequest();
        $userAgent = $request->headers->get('User-Agent') ?? '';
        $path = $request->getPathInfo();
        $query = $request->getQueryString();
        $requestKey = 'request_time_' . microtime() . '-' . md5($path . $query . self::$clientIp);
        self::$firewallTime += microtime(true) - $blockStartTime;
        $data = [
            'ip' => self::$clientIp,
            'path' => $path,
            'query' => $query,
            'agent' => $userAgent,
            'firewallTime' => self::$firewallTime,
            'responseTime' => $responseTime,
            'isBotAgent' => self::$isBotAgent,
            'isBannedBot' => self::$isBannedBot,
            'isChallenge' => self::$isChallenge,
            'isRateLimited'=> self::$isRateLimited,
        ];
        $requestItem = $this->cache->getItem($requestKey);
        $requestItem->set(json_encode($data));
        // We temporary cache for 2 minutes
        // There will be a cron to store in the db every minute
        $requestItem->expiresAfter(120);
        $this->cache->save($requestItem);
    }
}