<?php

namespace Kyte\Core;

class Api
{
	public $appId = null;
    private $key = null;
    public $account = null;
    public $session = null;
    public $user = null;
    public $app = null;
    public $errorHandler = null;
    private $signature = null;
    private $utcDate = null;
    public $model;
    public $request;
    public $contentType;
    public $data;
    public $field = null;
    public $value = null;
    public $page_size;
    public $page_total;
    public $page_num = 1;
    public $total_count;
    public $total_filtered;
    public $response = [];
    public $defaultEnvironmentConstants = [
        'DEBUG' => false,
        'S3_DEBUG' => false,
        'KYTE_JS_CDN' => 'https://cdn.keyqcloud.com/kyte/js/stable/kyte.js',
        'ALLOW_ENC_HANDOFF' => true,
        'ALLOW_MULTILOGON' => false,
        'ALLOW_SAME_TXTOKEN' => false,
        'SESSION_TIMEOUT' => 3600,
        'SIGNATURE_TIMEOUT' => 3600,
        'USERNAME_FIELD' => 'email',
        'PASSWORD_FIELD' => 'password',
        'VERBOSE_LOG' => false,
        'IS_PRIVATE' => true,
        'RETURN_NO_MODEL' => true,
        'SESSION_RETURN_FK' => true,
        'PAGE_SIZE' => 50,
        'USE_SESSION_MAP' => false,
        'CHECK_SYNTAX_ON_IMPORT' => false,
        'STRICT_TYPING' => true,
        'KYTE_USE_SNS' => false,
    ];

	public function __construct() {
		$this->defineEnvironmentConstants();
		$this->loadModelsAndControllers();
		self::dbconnect();

		if (php_sapi_name() !== 'cli') {
			$imdsData = \Kyte\Util\IMDS::fetchMetadata();
			$this->response['imds'] = $imdsData;
			$this->errorHandler = \Kyte\Exception\ErrorHandler::getInstance($this);
			$this->errorHandler->register();
		}
	}

	private function defineEnvironmentConstants() {
		foreach ($this->defaultEnvironmentConstants as $key => $value) {
			if (!defined($key)) {
				define($key, $value);
				error_log("$key constant not defined...using defaults ($value)");
			}
		}

		if (PHP_SAPI !== 'cli' && PHP_SAPI !== 'phpdbg') {
			$lang = array_key_exists('HTTP_ACCEPT_LANGUAGE', $_SERVER) ? substr($_SERVER['HTTP_ACCEPT_LANGUAGE'], 0, 2) : 'en';
			$acceptLang = ['ja', 'en']; 
			define('APP_LANG', in_array($lang, $acceptLang) ? $lang : 'en');
		}
	}

	private function defineAppEnvironmentConstants($app) {
		$models = new \Kyte\Core\Model(KyteEnvironmentVariable);
		$models->retrieve('application', $app->id);
		$envVars = [];
		foreach($models->objects as $object) {
			$envVars[$object->key] = $object->value;
		}
		define("KYTE_APP_ENV", $envVars);
	}

	private function defineAppDataStore($app) {
		$models = new \Kyte\Core\Model(DataStore);
		$models->retrieve('application', $app->id);
		$envVars = [];
		foreach($models->objects as $object) {
			$envVars[$object->name] = [
				"bucket" => $object->bucketname,
				"region" => $object->region,
			];
		}
		define("KYTE_APP_DATASTORE", $envVars);
	}

	public static function addPrimaryKey(&$modeldef) {
		$modeldef['struct']['id'] = [
			'type'		=> 'i',
			'required'	=> true,
			'pk'		=> true,
			'size'		=> 11,
			'date'		=> false,
		];
	}

	public static function addKyteAttributes(&$modeldef) {
		$attributes = [
			'created_by' => ['type' => 'i', 'required' => false, 'size' => 11, 'unsigned' => true, 'date' => false],
			'date_created' => ['type' => 'i', 'required' => false, 'date' => true],
			'modified_by' => ['type' => 'i', 'required' => false, 'size' => 11, 'unsigned' => true, 'date' => false],
			'date_modified' => ['type' => 'i', 'required' => false, 'date' => true],
			'deleted_by' => ['type' => 'i', 'required' => false, 'size' => 11, 'unsigned' => true, 'date' => false],
			'date_deleted' => ['type' => 'i', 'required' => false, 'date' => true],
			'deleted' => ['type' => 'i', 'required' => false, 'size' => 1, 'unsigned' => true, 'default' => 0, 'date' => false],
		];
		$modeldef['struct'] = array_merge($modeldef['struct'], $attributes);
	}

	public static function dbconnect() {
		if (\Kyte\Core\DBI::$dbUser == KYTE_DB_USERNAME && \Kyte\Core\DBI::$dbName == KYTE_DB_DATABASE && \Kyte\Core\DBI::$dbHost == KYTE_DB_HOST) {
			return;
		}

		\Kyte\Core\DBI::setDbUser(KYTE_DB_USERNAME);
		\Kyte\Core\DBI::setDbPassword(KYTE_DB_PASSWORD);
		\Kyte\Core\DBI::setDbHost(KYTE_DB_HOST);
		\Kyte\Core\DBI::setDbName(KYTE_DB_DATABASE);
		\Kyte\Core\DBI::setCharset(KYTE_DB_CHARSET);
	}

	public static function dbappconnect($database, $username, $password, $host = KYTE_DB_HOST, $charset = KYTE_DB_CHARSET) {
		if (!$database || !$username || !$password) {
			throw new \Exception("Database parameters must be provided. Database: $database\tUsername: $username\tPassword: $password");
		}
		if ($host == null) {
			$host = KYTE_DB_HOST;
		}
		if (\Kyte\Core\DBI::$dbUser == $username && \Kyte\Core\DBI::$dbName == $database && \Kyte\Core\DBI::$dbHost == $host) {
			return;
		}

		\Kyte\Core\DBI::setDbNameApp($database);
		\Kyte\Core\DBI::setDbUserApp($username);
		\Kyte\Core\DBI::setDbPasswordApp($password);
		\Kyte\Core\DBI::setDbHostApp($host);
		\Kyte\Core\DBI::setCharset($charset);
	}

	public static function dbswitch($useApp = false) {
		\Kyte\Core\DBI::$useAppDB = $useApp;
	}

	public static function loadAppModels($app) {
		$models = new \Kyte\Core\Model(DataModel);
		$models->retrieve('application', $app->id);
		foreach($models->objects as $object) {
			$model_definition = json_decode($object->model_definition, true);
			$model_definition['appId'] = $app->identifier;
			define($model_definition['name'], $model_definition);
		}
	}

	public static function loadAppController($app, $controller_name) {
		$controller = new \Kyte\Core\ModelObject(constant("Controller"));
		if ($controller->retrieve("name", $controller_name, [["field" => "application", "value" => $app->id]])) {
			$code = bzdecompress($controller->code);
			eval($code);
		}
	}

	public static function loadAppControllers($app) {
		$controllers = new \Kyte\Core\Model(constant("Controller"));
		$controllers->retrieve("application", $app->id);
		foreach($controllers->objects as $object) {
			$code = bzdecompress($object->code);
			eval($code);
		}
	}

	private function loadModelsAndControllers() {
		$kyte_models = [];
		foreach (glob(__DIR__ . "/../Mvc/Model/*.php") as $filename) {
			$model_name = basename($filename, '.php');
			require_once($filename);
			if (VERBOSE_LOG) {
				error_log("Importing builtin model $model_name...");
			}
			self::addPrimaryKey($$model_name);
			define($model_name, $$model_name);
			$kyte_models[] = $$model_name;
		}
		define('KYTE_MODELS', $kyte_models);
	}

	public function route() {
		try {
			$this->appId = $_SERVER['HTTP_X_KYTE_APPID'] ?? null;
			$this->key = new \Kyte\Core\ModelObject(KyteAPIKey);
			$this->response = ['session' => '0', 'token' => '0', 'uid' => '0', 'txTimestamp' => (new \DateTime('now', new \DateTimeZone('UTC')))->format('U')];

			if ($this->appId !== null) {
				$this->app = new \Kyte\Core\ModelObject(Application);
				if (!$this->app->retrieve('identifier', $this->appId)) {
					throw new \Exception("CRITICAL ERROR: Unable to find application and perform context switch for app ID {$this->appId}.");
				}
				self::defineAppEnvironmentConstants($this->app);
				self::defineAppDataStore($this->app);
				self::loadAppModels($this->app);
				self::dbappconnect($this->app->db_name, $this->app->db_username, $this->app->db_password);
			}

			$this->session = $this->appId && $this->app->user_model && $this->app->username_colname && $this->app->password_colname
				? new \Kyte\Session\SessionManager(Session, constant($this->app->user_model), $this->app->username_colname, $this->app->password_colname, $this->appId, ALLOW_MULTILOGON, SESSION_TIMEOUT)
				: new \Kyte\Session\SessionManager(Session, KyteUser, USERNAME_FIELD, PASSWORD_FIELD, null, ALLOW_MULTILOGON, SESSION_TIMEOUT);
			
			$this->user = $this->session->getUser();
			$this->account = new \Kyte\Core\ModelObject(KyteAccount);

			if ($this->validateRequest()) {
				$this->appId !== null && self::loadAppController($this->app, $this->model);
				$controllerClass = class_exists('\\Kyte\Mvc\\Controller\\'.$this->model.'Controller') ? '\\Kyte\Mvc\\Controller\\'.$this->model.'Controller' : (class_exists($this->model.'Controller') ? $this->model.'Controller' : '\\Kyte\\Mvc\\Controller\\ModelController');
				$controller = new $controllerClass(defined($this->model) ? constant($this->model) : null, $this, APP_DATE_FORMAT, $this->response);
				if (!$controller) throw new \Exception("[ERROR] Unable to create controller for model: $controllerClass.");

				switch ($this->request) {
					case 'POST': $controller->new($this->data); break;
					case 'PUT': $controller->update($this->field, $this->value, $this->data); break;
					case 'GET': $controller->get($this->field, $this->value); break;
					case 'DELETE': $controller->delete($this->field, $this->value); break;
					default: throw new \Exception("[ERROR] Unknown HTTP request type: $this->request.");
				}

				self::dbconnect();
			} else {
				$this->generateSignature();
			}
		} catch (\Kyte\Exception\SessionException $e) {
			$this->handleException($e, 403);
		} catch (\Exception $e) {
			$this->handleException($e, 400);
		}

		$this->response += ['page_size' => $this->page_size, 'page_total' => $this->page_total, 'page_num' => $this->page_num, 'total_count' => $this->total_count, 'total_filtered' => $this->total_filtered, 'response_code' => 200];
		if (defined('LOG_RESPONSE')) {
			error_log(json_encode($this->response, JSON_PRETTY_PRINT));
		}
		echo json_encode($this->response);
	}

	private function handleException($e, $code) {
		http_response_code($code);
		$this->response = ['response_code' => $code] + $this->response;
		$this->response['error'] = $e->getMessage();
		if (defined('LOG_RESPONSE')) {
			error_log(json_encode($this->response, JSON_PRETTY_PRINT));
		}
		echo json_encode($this->response);
		exit(0);
	}

	private function cors() {
		$origin = $_SERVER['HTTP_ORIGIN'] ?? ($_SERVER['HTTP_REFERER'] ?? $_SERVER['REMOTE_ADDR']);
		header("Access-Control-Allow-Origin: $origin");
		header('Access-Control-Allow-Credentials: true');
		header("Content-Type: application/json; charset=utf-8");
		if ($_SERVER['REQUEST_METHOD'] === 'OPTIONS') {
			header("Access-Control-Allow-Methods: GET, PUT, POST, DELETE, HEAD, OPTION");
			header("Access-Control-Allow-Headers: " . ($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS'] ?? ''));
			exit(0);
		}
		return $_SERVER['REQUEST_METHOD'];
	}

	private function validateRequest() {
		$this->request = $this->cors();
		$this->contentType = $_SERVER['CONTENT_TYPE'] ?? '';

		if (strpos($this->contentType, 'json') !== false) {
			$this->data = json_decode(file_get_contents("php://input"), true);
		} else {
			parse_str(file_get_contents("php://input"), $this->data);
		}

		if (VERBOSE_LOG > 0) {
			error_log(print_r($this->data, true));
		}

		if (IS_PRIVATE) {
			$this->signature = $_SERVER['HTTP_X_KYTE_SIGNATURE'] ?? null;
			if (!$this->signature) {
				return false;
			}
		}

		$this->parseIdentityString($_SERVER['HTTP_X_KYTE_IDENTITY'] ?? null);
		if (!$this->account) {
			return false;
		}

		$this->page_size = intval($_SERVER['HTTP_X_KYTE_PAGE_SIZE'] ?? PAGE_SIZE);
		$this->page_num = intval($_SERVER['HTTP_X_KYTE_PAGE_IDX'] ?? 0);
		$this->response['draw'] = intval($_SERVER['HTTP_X_KYTE_DRAW'] ?? 0);
		$this->response += ['CONTENT_TYPE' => $this->contentType, 'transaction' => $this->request, 'engine_version' => \Kyte\Core\Version::get()];

		$path = ltrim($_SERVER['REQUEST_URI'], '/');
		$elements = explode('/', $path);
		if (count($elements) >= 1) {
			$this->model = $elements[0];
			$this->field = $elements[1] ?? null;
			$this->value = $elements[2] ?? null;

			$this->response['model'] = $this->model;
			$sub_account_api = new \Kyte\Core\ModelObject(KyteAPIKey);
			if (!$sub_account_api->retrieve('kyte_account', $this->account->id)) {
				throw new \Exception("[ERROR] Unable to find API information for the account");
			}

			$this->response += ['kyte_api' => API_URL, 'kyte_pub' => $sub_account_api->public_key, 'kyte_num' => $this->account->number, 'kyte_iden' => $sub_account_api->identifier, 'kyte_app_id' => $this->appId ?? '', 'account_id' => $this->account->id];

			if (IS_PRIVATE) {
				$this->verifySignature();
			}

			return true;
		}

		return false;
	}

	private function parseIdentityString($string) {
		$identity = explode('%', base64_decode(urldecode($string)));
		if (count($identity) != 4) {
			throw new \Kyte\Exception\SessionException("[ERROR] Invalid identity string: $this->request.");
		}

		$this->utcDate = new \DateTime($identity[2], new \DateTimeZone('UTC'));
		if (time() > $this->utcDate->format('U') + SIGNATURE_TIMEOUT) {
			throw new \Kyte\Exception\SessionException("API request has expired.");
		}

		if (!isset($identity[0]) || !$this->key->retrieve('public_key', $identity[0])) {
			throw new \Exception("API key not found.");
		}

		if (!$this->account->retrieve('number', $identity[3])) {
			throw new \Exception("[ERROR] Unable to find account for {$identity[3]}.");
		}

		$identity[1] = $identity[1] == 'undefined' ? "0" : $identity[1];
		$this->response['session'] = $identity[1];

		if ($identity[1] != "0") {
			$session_ret = $this->session->validate($identity[1]);
			$this->response['session'] = $session_ret['session']->sessionToken;
			$this->response['token'] = $session_ret['session']->txToken;
			$this->user = $session_ret['user'];
			$this->response += ['uid' => $this->user->id, 'name' => $this->user->name, 'email' => $this->user->email];

			if ($this->appId === null && $this->user->kyte_account != $this->account->id) {
				if (!$this->account->retrieve('id', $this->user->kyte_account)) {
					throw new \Exception("Unable to find account associated with the user");
				}
			}
		}
	}

	private function verifySignature() {
		$token = $this->response['token'];
		$secretKey = $this->key->secret_key;
		$identifier = $this->key->identifier;

		$hash1 = hash_hmac('SHA256', $token, $secretKey, true);
		$hash1str = hash_hmac('SHA256', $token, $secretKey, false);

		if (VERBOSE_LOG > 0) {
			error_log("hash1 " . hash_hmac('SHA256', $token, $secretKey));
		}

		$hash2 = hash_hmac('SHA256', $identifier, $hash1, true);
		$hash2str = hash_hmac('SHA256', $identifier, $hash1, false);

		if (VERBOSE_LOG > 0) {
			error_log("hash2 " . hash_hmac('SHA256', $identifier, $hash1));
		}

		$calculated_signature = hash_hmac('SHA256', $this->utcDate->format('U'), $hash2);

		if (VERBOSE_LOG > 0) {
			error_log("hash3 $calculated_signature");
			error_log("epoch " . $this->utcDate->format('U'));
		}

		if ($calculated_signature != $this->signature) {
			throw new \Kyte\Exception\SessionException("Calculated signature does not match provided signature.\nCalculated: $hash1str $hash2str $calculated_signature\nProvided: " . $this->signature);
		}
	}

	private function generateSignature() {
		if ($this->request === 'POST' && ALLOW_ENC_HANDOFF && isset($this->data['key'], $this->data['identifier'], $this->data['time'])) {
			$key = $this->data['key'];
			$identifier = $this->data['identifier'];
			$time = $this->data['time'];

			$obj = new \Kyte\Core\ModelObject(KyteAPIKey);
			if (!$obj->retrieve('public_key', $key, [['field' => 'identifier', 'value' => $identifier]])) {
				throw new \Exception("Invalid API access key");
			}

			$date = new \DateTime($time, new \DateTimeZone('UTC'));
			$this->data['token'] = ($this->data['token'] === 'undefined') ? '0' : $this->data['token'];

			$hash1 = hash_hmac('SHA256', $this->data['token'], $obj->secret_key, true);
			$hash2 = hash_hmac('SHA256', $identifier, $hash1, true);
			$this->response['signature'] = hash_hmac('SHA256', $date->format('U'), $hash2);
		}
	}
}
