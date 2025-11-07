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
        $entityManager = $this->doctrine->getManager();
        $connection = $entityManager->getConnection();
        $cacheInspector = new CacheInspector($this->cache);
        foreach ($cacheInspector->getKeysByPrefix('request_time_') as $key) {
            $item = $this->cache->getItem($key);
            if ($item->isHit()) {
                $cacheItem = json_decode($item->get(), true);
                var_dump($cacheItem);
                // Delete cache item
                $this->cache->deleteItem($key);
            }
            
        }

        return Command::SUCCESS;
    }
}
