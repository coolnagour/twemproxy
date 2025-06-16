<?php

/**
Checks for new read hostnames. for example redis on AWS can have muliple read enpoints behind a xxx-ro...euw1.cache.amazonaws.com URL
This watches for any new DNS entries and updates the config file, and sends a SIGHUP to nutcracker

you will already need a config.yml file created with 2 pools. one with the read endpoint (-ro in the URL) and another with a write

*/

$forceUpdate = false;
$verbose = true;
$nohup = false;

foreach ($argv as $arg) {

    if (in_array($arg, ['--force', '-f'])) {
        $forceUpdate = true;
        echo 'force updating configs' . PHP_EOL;
    }

    if (in_array($arg, ['--verbose', '-v'])) {
        $verbose = true;
        echo 'running in verbose mode' . PHP_EOL;
    }

    if (in_array($arg, ['--reload', '-r'])) {
        $nohup = true;
        echo 'reloading' . PHP_EOL;
    }
}
if (isset($argv[1]) && $argv[1] == 'force') {
    $forceUpdate = true;
}

$updater = new redisProxy($verbose);
if ($forceUpdate) {
    $updater->forceUpdate($nohup);
} else {
    $updater->process();
}



class redisProxy
{


    const CONFIG_FILE = '/usr/bin/nutcracker/conf/nutcracker.yml';
    const DYNAMIC_HOST = 'dynamicallyAdded';
    const SLEEP_BETWEEN_DNS_CHECKS = 3;
    const DNS_CHECKS = 3;

    const CYAN = "\033[36m";
    const GREEN = "\033[92m";
    const RED = "\033[91m";


    protected $verbose = false;
    protected $update = false;
    protected $uncleanShutdown = false;

    protected $connections = [];

    public function __construct($verbose = false)
    {
        $this->verbose = $verbose;

        $this->lockFile = self::CONFIG_FILE . '.updater-lock';
        register_shutdown_function([$this, 'shutdown']);
        $this->setReadWrite(); // loads all the configs of existing yml file into memory

    }

    public function logger($log, $color = '')
    {
        $clearColor = '';
        if (!empty($color)) {
            $clearColor =  "\033[0m";
        }

        echo $color . '[' .  date('Y-m-d H:i:s') . '] ' . $log . $clearColor . PHP_EOL;
    }

    public function process()
    {
        $this->logger('starting up', self::CYAN);
        $randSleep = rand(1,5);
        $this->logger('sleeping for ' . $randSleep . ' seconds', self::CYAN);
        sleep($randSleep);
        $start = time();
        $this->checkForLock();
        $this->checkForNewHosts();

    
        $this->checkHostHealth();
        $this->processUpdates();
        sleep(4);

        $this->logger('done' . self::CYAN);
    }


    public function forceUpdate($nohup = false)
    {
        $this->updateHosts($nohup);
    }



    function checkForLock()
    {

        if (file_exists($this->lockFile)) {
            if (filemtime($this->lockFile) > time() - 360) {
                $this->uncleanShutdown = true;
                die($this->lockFile . ' exists. Process already running' . PHP_EOL);
            } else {
                unlink($this->lockFile);
            }
        }
        file_put_contents($this->lockFile, time());
    }

    function shutdown()
    {
        if (!$this->uncleanShutdown) {
            if (file_exists($this->lockFile)) {
                unlink($this->lockFile);
            }
        }
    }



    function checkHostHealth()
    {
        if (!empty($this->readHosts)) {

            foreach ($this->readHosts as $key => $host) {
                if (!$this->isHostHealthy($host)) {
                    unset($this->readHosts[$key]);
                    $this->update = true;
                }
            }

            if (empty($this->readHosts)) {
                die('all hosts got removed, could be a DNS issue. will not continue' . PHP_EOL);
            }
        }
    }


    function isHostHealthy($host)
    {
        try {
            if (!isset($this->connections[$host])) {
                //dont want every server to connect at the same cron job time, used for sleep
                $rand = 100 + rand(500, 2000);

                if ($this->verbose) {
                    $this->logger('connecting to ' . $host  . ' with sleep of ' . $rand . 'ms');
                }

                usleep($rand);

                $this->connections[$host] = new Redis();
                $this->connections[$host]->connect($host, 6379, 2.5);
            }

            $pongResponse = $this->connections[$host]->ping();
            if ($pongResponse == '1') {
                if ($this->verbose) {
                    $this->logger($host . ' redis ping ok');
                }
                try {
                    $write =  $this->connections[$host]->set('key','value', 10);
                    if($write){
                        $this->logger($host . ' we can write, but this should be a read only endpoint', self::RED);
                        return false;
                    }
                } catch (Exception $e) {
                    $this->logger($host . ' checked that is is a reader');
                }
                return true;
            } else {
                $this->logger($host . ' bad redis ping', self::RED);
                return false;
            }
        } catch (Exception $e) {
            $this->logger($host . ' is down (' . $e->getMessage() . ') removing from list', self::RED);
            return false;
        }
    }


    function checkForNewHosts()
    {

        $checkedHosts = [];
        $count = 0;
        while ($count < self::DNS_CHECKS) {
            $count++;

            $dns = dns_get_record($this->read);
          
            foreach ($dns as $record) {
                if ($record['type'] === 'CNAME' && isset($record['target'])) {

                    $host = $record['target'];
                    if (!in_array($host, $this->readHosts)) {

                        if(!in_array($host, $checkedHosts)) {

                            if ($this->isHostHealthy($host)) {
                                $this->logger('new host detected ' . $host, self::GREEN);
                                $this->update = true;
                                $this->readHosts[] = $record['target'];
                            } else {
                                $this->logger('new host detected but it is not responding yet.. will wait until it responds: ' . $host, self::RED);
                            }
                            $checkedHosts[] = $host;
                        }else{
                            $this->logger('we have already checked ' . $host, self::GREEN);
                        }
                    }else{
                        $this->logger('we know about ' . $host, self::GREEN);
                    }
                }
            }

            sleep(self::SLEEP_BETWEEN_DNS_CHECKS);
        }
    }


    function processUpdates()
    {
        if ($this->update == true) {
            $this->update = false;
            $this->logger('Dynamic read hosts are ' . implode(', ', $this->readHosts));
            $this->updateHosts();
        }
    }






    function setReadWrite()
    {
        $file = file_get_contents(self::CONFIG_FILE);
        $lines = explode("\n", $file);
        $read = '';
        $write = '';
        $dynamicReadHosts = [];
        $now = time();
        foreach ($lines as $line) {
         
          //dirty way of finding the hostname instead of parsing yaml, as the line contains 6379
          
            if (strpos($line, '6379') !== false) {
              
               //- blah-ro.hostname.com:6379:1 hostName
                $serverParts = explode(':', $line);
              
                //- blah-ro.hostname.com
                $host = $serverParts[0];
              
                //blah-ro.hostname.com
                $host = ltrim($host, "- \t");
               
                if (strpos($line, self::DYNAMIC_HOST) !== false) { //we add this tag to all read endpoint names
                    $dynamicReadHosts[] = $host;
                } elseif (strpos($host, '-ro') !== false) { //read only endpoint
                    $read = $host;
                } else {
                    $write = $host;
                }
            }
        }

        if (empty($read)) {
            die('no read endpoint found');
        }

        if (empty($write)) {
            die('no write endpoint found');
        }

        $dynamicReadHosts = array_unique($dynamicReadHosts);
        if ($this->verbose) {
            $this->logger('write: ' . $write);
            $this->logger('read: ' . $read);
            $this->logger('readDynamic: ' . implode(', ', $dynamicReadHosts));
        }

        $this->read = $read;
        $this->write = $write;
        $this->readHosts = $dynamicReadHosts;
    }



    function updateHosts($NOHUP = true)
    {

        $this->logger('updating ' . self::CONFIG_FILE);


        $extraReadHosts = '# The following hosts were dynamically added by the cron job ' . __FILE__ . PHP_EOL;
        $i = 1;
        foreach ($this->readHosts as $readHost) {
            $name = explode('.', $readHost);
            $extraReadHosts .= '            - ' . $readHost . ':6379:10000 ' . self::DYNAMIC_HOST . '-' . $i . '-' . $name[0] . PHP_EOL;
            $i++;
        }


        $config = "
global:
    worker_processes: auto      # num of workers, fallback to single process model while worker_processes is 0
    max_openfiles: 102400       # max num of open files in every worker process
    user: nobody                # user of worker's process, master process should be setup with root
    group: nobody               # group of worker's process
    worker_shutdown_timeout: 30 # terminate the old worker after worker_shutdown_timeout, unit is second

pools:
    write:
        listen: 127.0.0.1:6379
        auto_eject_hosts: true
        redis: true
        timeout: 2000
        server_retry_timeout: 1000
        server_failure_limit: 5
        server_connections: 1
        servers:
            - $this->write:6379:1


    read:
        listen: 127.0.0.1:6378
        distribution: ketama
        auto_eject_hosts: true
        redis: true
        timeout: 2000
        server_retry_timeout: 10000
        server_failure_limit: 1
        server_connections: 1
        servers:
            - $this->read:6379:1 PrimaryReadEndpoint
" . $extraReadHosts;



        echo exec('sudo mv ' . self::CONFIG_FILE . ' ' . self::CONFIG_FILE . '.' . time() . '.backup');
        echo exec('sudo find ' . self::CONFIG_FILE . '*.backup -mtime +5 -exec rm {} \;');

        file_put_contents(self::CONFIG_FILE, $config);

        if ($NOHUP) {
            $this->logger('sending SIGHUP to nutcracker');
            echo exec('sudo pkill -1 nutcracker');
            $this->logger('config reloaded, sleeping loop to give it time to rest before another possible reload');
            sleep(9);
        }
        
    }
}
