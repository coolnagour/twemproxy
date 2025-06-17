<?php
/**
 * Redis Load Test Script
 * Tests Redis server performance with multiple connections and GET commands
 */

// Configuration
$host = '127.0.0.1';
$writePort = 6379;
$port = 6378;
$num_connections = 100;
$commands_per_connection = 10000;
$test_key_prefix = 'test_key_';

echo "Redis Load Test Starting...\n";
echo "Host: $host:$port\n";
echo "Connections: $num_connections\n";
echo "Commands per connection: $commands_per_connection\n";
echo "Total commands: " . ($num_connections * $commands_per_connection) . "\n\n";

// First, populate some test data
echo "Setting up test data...\n";
try {
    $redis = new Redis();
    $redis->connect($host, $writePort, 2.5);
    
    // Set some test keys
    for ($i = 1; $i <= 1000; $i++) {
        $redis->setex($test_key_prefix . $i, 86400, "test_value_$i");
    }
    $redis->close();
    echo "Test data setup complete.\n\n";
} catch (Exception $e) {
    echo "Error setting up test data: " . $e->getMessage() . "\n";
    exit(1);
}

// Function to run load test for a single connection
function runConnectionTest($host, $port, $connection_id, $commands_per_connection, $test_key_prefix) {
    $start_time = microtime(true);
    $errors = 0;
    $successful_commands = 0;
    
    try {
        $redis = new Redis();
        $connect_result = $redis->connect($host, $port, 2.5);
        
        if (!$connect_result) {
            return [
                'connection_id' => $connection_id,
                'success' => false,
                'error' => 'Failed to connect',
                'commands_executed' => 0,
                'execution_time' => 0,
                'errors' => 1
            ];
        }
        
        // Execute GET commands
        for ($i = 0; $i < $commands_per_connection; $i++) {
            $key_num = rand(1, 1000);
            $key = $test_key_prefix . $key_num;
            
            try {
                $result = $redis->get($key);
                if ($result !== false) {
                    $successful_commands++;
                } else {
                    $errors++;
                }
            } catch (Exception $e) {
                $errors++;
            }
        }
        
        $redis->close();
        
    } catch (Exception $e) {
        return [
            'connection_id' => $connection_id,
            'success' => false,
            'error' => $e->getMessage(),
            'commands_executed' => $successful_commands,
            'execution_time' => microtime(true) - $start_time,
            'errors' => $errors + 1
        ];
    }
    
    $execution_time = microtime(true) - $start_time;
    
    return [
        'connection_id' => $connection_id,
        'success' => true,
        'commands_executed' => $successful_commands,
        'execution_time' => $execution_time,
        'errors' => $errors,
        'commands_per_second' => $successful_commands / $execution_time
    ];
}

// Run the load test
echo "Starting load test...\n";
$overall_start = microtime(true);
$results = [];

while(true){

// Use process forking for true concurrency (if available)
if (function_exists('pcntl_fork')) {
    echo "Using process forking for concurrent connections...\n";
    $pids = [];
    
    for ($i = 0; $i < $num_connections; $i++) {
        $pid = pcntl_fork();
        
        if ($pid == -1) {
            die("Could not fork process $i\n");
        } elseif ($pid == 0) {
            // Child process
            $result = runConnectionTest($host, $port, $i + 1, $commands_per_connection, $test_key_prefix);
            echo "Connection " . ($i + 1) . " completed: " . 
                 $result['commands_executed'] . " commands, " . 
                 number_format($result['execution_time'], 3) . "s, " .
                 $result['errors'] . " errors\n";
            exit(0);
        } else {
            // Parent process
            $pids[] = $pid;
        }
    }
    
    // Wait for all child processes to complete
    foreach ($pids as $pid) {
        pcntl_waitpid($pid, $status);
    }
    
} else {
    // Fallback to sequential execution
    echo "Process forking not available, running sequentially...\n";
    
    for ($i = 0; $i < $num_connections; $i++) {
        $result = runConnectionTest($host, $port, $i + 1, $commands_per_connection, $test_key_prefix);
        $results[] = $result;
        
        echo "Connection " . ($i + 1) . " completed: ";
        if ($result['success']) {
            echo $result['commands_executed'] . " commands, " . 
                 number_format($result['execution_time'], 3) . "s, " .
                 number_format($result['commands_per_second'], 2) . " cmd/s, " .
                 $result['errors'] . " errors\n";
        } else {
            echo "FAILED - " . $result['error'] . "\n";
        }
    }
    
    $overall_time = microtime(true) - $overall_start;
    
    // Calculate statistics
    $total_commands = 0;
    $total_errors = 0;
    $successful_connections = 0;
    
    foreach ($results as $result) {
        $total_commands += $result['commands_executed'];
        $total_errors += $result['errors'];
        if ($result['success']) {
            $successful_connections++;
        }
    }
    
    echo "\n" . str_repeat("=", 50) . "\n";
    echo "LOAD TEST RESULTS\n";
    echo str_repeat("=", 50) . "\n";
    echo "Total execution time: " . number_format($overall_time, 3) . " seconds\n";
    echo "Successful connections: $successful_connections / $num_connections\n";
    echo "Total commands executed: $total_commands\n";
    echo "Total errors: $total_errors\n";
    echo "Overall commands per second: " . number_format($total_commands / $overall_time, 2) . "\n";
    echo "Success rate: " . number_format((($total_commands - $total_errors) / $total_commands) * 100, 2) . "%\n";
}

echo "\nLoad test completed!\n";
}
?>