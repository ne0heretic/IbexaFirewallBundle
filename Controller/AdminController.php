<?php

namespace Ne0Heretic\FirewallBundle\Controller;

use Ibexa\Contracts\AdminUi\Controller\Controller;
use Ibexa\Core\MVC\Symfony\Security\Authorization\Attribute;
use Pagerfanta\Pagerfanta;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Cache\Adapter\RedisTagAwareAdapter;
use Symfony\Bridge\Doctrine\ManagerRegistry;

class AdminController extends Controller
{
    /** @var RedisTagAwareAdapter */
    protected $cache;
    /** @var string */
    protected $cacheDir;
    public function __construct(
        RedisTagAwareAdapter $cache,
        string $cacheDir,
        ManagerRegistry $doctrine
    )
    {
        $this->cache = $cache;
        $this->cacheDir = $cacheDir;
        $this->doctrine = $doctrine;
    }

    public function performAccessCheck(): void
    {
        parent::performAccessCheck();
        $this->denyAccessUnlessGranted(new Attribute('ne0heretic_firewall', 'admin'));
    }

    public function dashboardAction()
    {
        $this->performAccessCheck();
        $pathItems = [
            ['value' => 'Ibexa Firewall'],
        ];
        $params = [
            'title' => 'Ibexa Firewall: Dashboard',
            'path_items' => $pathItems,
        ];
        $request = Request::createFromGlobals();
        $entityManager = $this->doctrine->getManager();
        $connection = $entityManager->getConnection();
        $request = Request::createFromGlobals();

        // Fetch latest server metrics from cache or DB
        $metricsCacheItem = $this->cache->getItem('ne0heretic_server_metrics');
        if ($metricsCacheItem->isHit()) {
            $latestMetrics = json_decode($metricsCacheItem->get(), true);
        } else {
            $latestMetrics = $connection->fetchAssociative('SELECT * FROM server_metrics ORDER BY timestamp DESC LIMIT 1');
            if ($latestMetrics) {
                $metricsCacheItem->set(json_encode($latestMetrics));
                $this->cache->save($metricsCacheItem);
            }
        }
        $params['latestMetrics'] = $latestMetrics ?? [];

        // Fetch HTTP request log aggregates for today
        $today = date('Y-m-d');
        $requestStats = [
            'total' => (int) $connection->fetchOne("SELECT COUNT(*) FROM http_request_logs WHERE DATE(timestamp) = ?", [$today]),
            'bots' => (int) $connection->fetchOne("SELECT COUNT(*) FROM http_request_logs WHERE isBotAgent = 1 AND DATE(timestamp) = ?", [$today]),
            'bannedBots' => (int) $connection->fetchOne("SELECT COUNT(*) FROM http_request_logs WHERE isBannedBot = 1 AND DATE(timestamp) = ?", [$today]),
            'challenges' => (int) $connection->fetchOne("SELECT COUNT(*) FROM http_request_logs WHERE isChallenge = 1 AND DATE(timestamp) = ?", [$today]),
            'rateLimited' => (int) $connection->fetchOne("SELECT COUNT(*) FROM http_request_logs WHERE isRateLimited = 1 AND DATE(timestamp) = ?", [$today]),
        ];
        $params['requestStats'] = $requestStats;

        // Fetch recent requests (last 10)
        $recentRequests = $connection->fetchAllAssociative(
            "SELECT ip, path, query, agent, firewallTime, responseTime, isBotAgent, isBannedBot, isChallenge, isRateLimited, timestamp
             FROM http_request_logs
             ORDER BY timestamp DESC
             LIMIT 10"
        );
        $params['recentRequests'] = $recentRequests;

        // Fetch top 5 paths by request count today
        $topPaths = $connection->fetchAllAssociative(
            "SELECT path, COUNT(*) as count
             FROM http_request_logs
             WHERE DATE(timestamp) = ?
             GROUP BY path
             ORDER BY count DESC
             LIMIT 5",
            [$today]
        );
        $params['topPaths'] = $topPaths;

        return $this->render('@ibexadesign/ne0heretic/pages/dashboard.html.twig', $params);
    }
}