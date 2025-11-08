<?php

namespace Ne0Heretic\FirewallBundle\Command;

use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Component\Cache\Adapter\RedisTagAwareAdapter;
use Symfony\Bridge\Doctrine\ManagerRegistry;
use Ne0Heretic\FirewallBundle\Lib\CacheInspector;

class StoreDataCommand extends Command
{
    /**
     * @var ManagerRegistry
     */
    private $doctrine;
    /** @var RedisTagAwareAdapter */
    protected $cache;

    public function __construct(RedisTagAwareAdapter $cache, ManagerRegistry $doctrine)
    {
        parent::__construct(null);
        $this->doctrine = $doctrine;
        $this->cache = $cache;
    }

    protected function configure()
    {
        $this
                ->setName('ibexa:firewall:store')
                ->setDescription('Stores Ibexa Firewall cached data into the database');
    }

    protected function initialize(InputInterface $input, OutputInterface $output)
    {
        parent::initialize($input, $output);
    }

    protected function execute(InputInterface $input, OutputInterface $output)
    {
        $serverData = [];
        $nproc = floatval(trim(shell_exec('nproc')));
        $cpuLoad = floatval(shell_exec("cat /proc/loadavg | awk '{print $1}'"));
        $serverData['cpu'] = 100*($cpuLoad/$nproc);
        $serverData['memory'] = 100*floatval(shell_exec('free -m | awk \'NR==2{printf "%.4f", $3/$2}\''));
        // Function to get memory % for a service (sum of %MEM for matching processes)
        function getServiceMemoryPercent($servicePattern) {
            $cmd = "ps -eo %mem,cmd --no-headers 2>/dev/null | grep -i " . escapeshellarg("[$servicePattern[0]]" . substr($servicePattern, 1)) . " | awk '{sum += \$1} END {printf \"%.4f\", sum}'";
            return floatval(trim(shell_exec($cmd)));
        }

        // Get memory % for each service
        $serverData['redis_mem'] = getServiceMemoryPercent('redis-server');
        $serverData['apache2_mem'] = getServiceMemoryPercent('apache2');
        $serverData['varnish_mem'] = getServiceMemoryPercent('varnishd');
        $serverData['mysql_mem'] = getServiceMemoryPercent('mysqld');
        // Store server data
        $entityManager = $this->doctrine->getManager();
        $connection = $entityManager->getConnection();
        $insertSql = "
            INSERT INTO server_metrics
            (cpu, memory, redis_mem, apache2_mem, varnish_mem, mysql_mem) VALUES (?, ?, ?, ?, ?, ?)
        ";
        $params = [
            $serverData['cpu'],
            $serverData['memory'],
            $serverData['redis_mem'],
            $serverData['apache2_mem'],
            $serverData['varnish_mem'],
            $serverData['mysql_mem']
        ];
        $connection->executeStatement($insertSql, $params);
        // also store in redis
        $metricsItem = $this->cache->getItem('ne0heretic_server_metrics');
        $serverData['timestamp'] = time();
        $metricsItem->set(json_encode($serverData));
        $this->cache->save($metricsItem);
        // Now process requests data
        $cacheInspector = new CacheInspector($this->cache);
        foreach ($cacheInspector->getKeysByPrefix('request_time_') as $key) {
            $item = $this->cache->getItem($key);
            if ($item->isHit()) {
                $dataJson = $item->get();
                $data = json_decode($dataJson, true);
                $insertItemSql = "INSERT INTO http_request_logs (ip, path, query, agent, firewallTime, responseTime, isBotAgent, isBannedBot, isChallenge, isRateLimited) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                $itemParams = [
                    $data['ip'],
                    $data['path'],
                    $data['query'],
                    $data['agent'],
                    $data['firewallTime'],
                    $data['responseTime'],
                    $data['isBotAgent'] ? 1 : 0,
                    $data['isBannedBot'] ? 1 : 0,
                    $data['isChallenge'] ? 1 : 0,
                    $data['isRateLimited'] ? 1 : 0
                ];
                $output->writeln(implode(' ', $data));
                $connection->executeStatement($insertItemSql, $itemParams);
                // Delete cache item
                $this->cache->deleteItem($key);
            }

        }

        return Command::SUCCESS;
    }
}
