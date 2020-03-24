<?php

    require_once __DIR__.'/config.php';

    /* load classes from composer */
	require 'vendor/autoload.php';
	// include any utility scripts
	foreach (glob("util/*.php") as $filename) {
		require_once($filename) ;
    }
    
	// include models being used by app
    foreach (glob("models/*.php") as $filename) {
        require_once($filename);
        $model_name = substr($filename, 0, strrpos($filename, "."));
        define($model_name, $$model_name);
    }
    
    // include any controllers
	foreach (glob("controllers/*.php") as $filename) {
		require_once($filename) ;
    }
    
?>
