<?php
    /* LOG OUTPUT */
    define('VERBOSE_LOG', false);

    /* LOCALIZATION SUPPORT */
    // default to English
    $lang = 'en';
    // determine browser local
    if (array_key_exists('HTTP_ACCEPT_LANGUAGE', $_SERVER)) {
        $lang = substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2);
    }
	
	// supported languages - add additional language support here
	$acceptLang = ['ja', 'en']; 
	define('APP_LANG', in_array($lang, $acceptLang) ? $lang : 'en');

    /* load classes from composer */
	require 'vendor/autoload.php';
	// include any utility scripts
	foreach (glob("util/*.php") as $filename) {
        require_once($filename) ;
    }

    // load base controller
    require 'builtin/controllers/ModelController.php';
    
    /* Load user-defined files first in case there are overrides */
    if ( file_exists( "app/" ) && is_dir( "app/" ) ) {
        if ( file_exists( "app/models/" ) && is_dir( "app/models/" ) ) {
            // load user defined models and controllers (allow override of builtin)
            foreach (glob("app/models/*.php") as $filename) {
                require_once($filename);
                $model_name = substr($filename, 0, strrpos($filename, "."));
                $model_name = str_replace('app/models/','',$model_name);
                if (VERBOSE_LOG) {
                    error_log("Loading user defined model $model_name");
                    error_log("Checking if user defined model has been defined...".(isset($$model_name) ? 'defined!' : 'UNDEFINED!'));
                }
                define($model_name, $$model_name);
            }
        }
        if ( file_exists( "app/controllers/" ) && is_dir( "app/controllers/" ) ) {
            // include any controllers
            foreach (glob("app/controllers/*.php") as $filename) {
                $controller_name = substr($filename, 0, strrpos($filename, "."));
                $controller_name = str_replace('app/controllers/','',$controller_name);
                require_once($filename);
                if (VERBOSE_LOG) {
                    error_log("Checking if user defined controller has been defined...".(class_exists($controller_name) ? 'defined!' : 'UNDEFINED!'));
                }
            }
        }      
    } 

	// include models being used by app
    foreach (glob("builtin/models/*.php") as $filename) {
        $model_name = substr($filename, 0, strrpos($filename, "."));
        $model_name = str_replace('builtin/models/','',$model_name);
        if (isset($$model_name)) {
            if (VERBOSE_LOG) {
                error_log("Skipping model $model_name as already defined...");
            }
        } else {
            require_once($filename);
            if (VERBOSE_LOG) {
                error_log("Checking if model has been defined...".(isset($$model_name) ? 'defined!' : 'UNDEFINED!'));
            }
            define($model_name, $$model_name);
        }
    }
    
    // include any controllers
	foreach (glob("builtin/controllers/*.php") as $filename) {
        $controller_name = substr($filename, 0, strrpos($filename, "."));
        $controller_name = str_replace('builtin/controllers/','',$controller_name);
        if (class_exists($controller_name)) {
            if (VERBOSE_LOG) {
                error_log("Skipping controller $filename as already defined...");
            }
        } else {
            require_once($filename);
            if (VERBOSE_LOG) {
                error_log("Checking if controller has been defined...".(class_exists($controller_name) ? 'defined!' : 'UNDEFINED!'));
            }
        }
    }

    require_once __DIR__.'/config.php';
    
?>
