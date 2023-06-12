<?php

namespace Kyte\Core;

/**
 * Class Api
 *
 * This class represents the API and handles the routing of requests.
 *
 * @package Kyte\Core
 */
class Api
{
	/**
     * The application ID.
     *
     * @var string|null
     */
	public $appId = null;

	/**
     * @var \Kyte\Core\ModelObject The APIKey model object.
     */
    private $key = null;
    
    /**
     * * @var \Kyte\Core\ModelObject The KyteAccount model object.
     */
    public $account = null;
    
    /**
     * * @var \Kyte\Core\ModelObject The Session model object.
     */
    public $session = null;
    
    /**
     * @var \Kyte\Core\ModelObject The User model object.
     */
    public $user = null;
    
    /**
     * @var \Kyte\Core\ModelObject The Application model object.
     */
    public $app = null;
    
    /**
     * The API signature.
     *
     * @var string|null
     */
    private $signature = null;
    
    /**
     * The UTC date.
     *
     * @var mixed|null
     */
    private $utcDate = null;
    
    /**
     * The HTTP request model.
     *
     * @var string|null
     */
    public $model;
    
    /**
     * The HTTP request.
     *
     * @var mixed|null
     */
    public $request;
    
    /**
     * The content type.
     *
     * @var mixed|null
     */
    public $contentType;
    
    /**
     * The request data.
     *
     * @var array<string,mixed>|null
     */
    public $data;
    
    /**
     * The field.
     *
     * @var string|null
     */
    public $field = null;
    
    /**
     * The value.
     *
     * @var string|null
     */
    public $value = null;
    
    /**
     * The page size.
     *
     * @var int|null
     */
    public $page_size;
    
    /**
     * The total number of pages.
     *
     * @var int|null
     */
    public $page_total;
    
    /**
     * The current page number.
     *
     * @var int
     */
    public $page_num = 1;
    
    /**
     * The total count.
     *
     * @var int|null
     */
    public $total_count;
    
    /**
     * The total filtered count.
     *
     * @var int|null
     */
    public $total_filtered;
    
    /**
     * The response data.
     *
     * @var array<string,mixed>
     */
    public $response = [];
	

	/**
     * Api constructor.
     *
     * Initializes the base framework and sets up the environment constants.
     */
	public function __construct() {
		$this->defineEnvironmentConstants();
		$this->loadModelsAndControllers();
	
		// initialize base framework
		self::dbconnect();
	}

	/**
     * Defines the environment constants.
     *
     * This method defines various constants required by the API if they are not already defined.
     */
	private function defineEnvironmentConstants() {
		if (!defined('DEBUG')) {
			define('DEBUG', false);
			error_log('DEBUG constant not defined...using defaults');
		}
		// compatibility for older config files
		if (!defined('ALLOW_ENC_HANDOFF')) {
			define('ALLOW_ENC_HANDOFF', true);
			error_log('ALLOW_ENC_HANDOFF constant not defined...using defaults');
		}
		if (!defined('ALLOW_MULTILOGON')) {
			define('ALLOW_MULTILOGON', false);
			error_log('ALLOW_MULTILOGON constant not defined...using defaults');
		}
		if (!defined('ALLOW_SAME_TXTOKEN')) {
			define('ALLOW_SAME_TXTOKEN', false);
			error_log('ALLOW_SAME_TXTOKEN constant not defined...using defaults');
		}
		if (!defined('SESSION_TIMEOUT')) {
			define('SESSION_TIMEOUT', 3600);
			error_log('SESSION_TIMEOUT constant not defined...using defaults');
		}
		if (!defined('USERNAME_FIELD')) {
			define('USERNAME_FIELD', 'email');
			error_log('USERNAME_FIELD constant not defined...using defaults');
		}
		if (!defined('PASSWORD_FIELD')) {
			define('PASSWORD_FIELD', 'password');
			error_log('PASSWORD_FIELD constant not defined...using defaults');
		}
		if (!defined('VERBOSE_LOG')) {
			define('VERBOSE_LOG', false);
			error_log('VERBOSE_LOG constant not defined...using defaults');
		}
		if (!defined('IS_PRIVATE')) {
			define('IS_PRIVATE', true);
			error_log('IS_PRIVATE constant not defined...using defaults');
		}
		if (!defined('RETURN_NO_MODEL')) {
			define('RETURN_NO_MODEL', true);
			error_log('RETURN_NO_MODEL constant not defined...using defaults');
		}
		if (!defined('SESSION_RETURN_FK')) {
			define('SESSION_RETURN_FK', true);
			error_log('SESSION_RETURN_FK constant not defined...using defaults');
		}
		if (!defined('PAGE_SIZE')) {
			define('PAGE_SIZE', 50);
			error_log('PAGE_SIZE constant not defined...using defaults');
		}
		if (!defined('USE_SESSION_MAP')) {
			define('USE_SESSION_MAP', false);
			error_log('USE_SESSION_MAP constant not defined...using defaults');
		}
		if (!defined('CHECK_SYNTAX_ON_IMPORT')) {
			define('CHECK_SYNTAX_ON_IMPORT', false);
			error_log('CHECK_SYNTAX_ON_IMPORT constant not defined...using defaults');
		}
		if (!defined('STRICT_TYPING')) {
			define('STRICT_TYPING', true);
			error_log('STRICT_TYPING constant not defined...using defaults');
		}

		// determine localizations for non-cli requests
		if (PHP_SAPI !== 'cli' && PHP_SAPI !== 'phpdbg') {
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
		}
	}

	/**
     * Adds a primary key to the model definition.
     *
     * @param array $modeldef The model definition to add the primary key to.
     */
	public static function addPrimaryKey(&$modeldef) {
		$modeldef['struct']['id'] = [
			'type'		=> 'i',
			'required'	=> true,
			'pk'		=> true,
			'size'		=> 11,
			'date'		=> false,
		];
	}

	/**
     * Adds audit attributes to the model definition.
     *
     * @param array $modeldef The model definition to add the audit attributes to.
     */
	public static function addKyteAttributes(&$modeldef) {
		$modeldef['struct']['created_by'] = [
			'type'		=> 'i',
			'required'	=> false,
			'size'		=> 11,
			'unsigned'	=> true,
			'date'		=> false,
		];

		$modeldef['struct']['date_created'] = [
			'type'		=> 'i',
			'required'	=> false,
			'date'		=> true,
		];

		$modeldef['struct']['modified_by'] = [
			'type'		=> 'i',
			'required'	=> false,
			'size'		=> 11,
			'unsigned'	=> true,
			'date'		=> false,
		];

		$modeldef['struct']['date_modified'] = [
			'type'		=> 'i',
			'required'	=> false,
			'date'		=> true,
		];

		$modeldef['struct']['deleted_by'] = [
			'type'		=> 'i',
			'required'	=> false,
			'size'		=> 11,
			'unsigned'	=> true,
			'date'		=> false,
		];

		$modeldef['struct']['date_deleted'] = [
			'type'		=> 'i',
			'required'	=> false,
			'date'		=> true,
		];

		$modeldef['struct']['deleted'] = [
			'type'		=> 'i',
			'required'	=> false,
			'size'		=> 1,
			'unsigned'	=> true,
			'default'	=> 0,
			'date'		=> false,
		];
	}

	/**
     * Sets database credentials to the default database.
     */
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

	/**
     * Sets database credentials to the specified app database.
     *
     * @param string $database The name of the database to connect to.
     * @param string $username The username for the database connection.
     * @param string $password The password for the database connection.
     * @param string|null $host The host for the database connection. Defaults to the value of KYTE_DB_HOST.
     * @param string|null $charset The charset for the database connection. Defaults to the value of KYTE_DB_CHARSET.
     * @throws \Exception If the database parameters are not provided.
     */
	public static function dbappconnect($database, $username, $password, $host = KYTE_DB_HOST, $charset = KYTE_DB_CHARSET) {
		if ($database == null || $username == null || $password == null) {
			throw new \Exception("Database parameters must be provided. Database: $database\tUsername: $username\tPassword: $password");
		}
		if ($host == null) {
			$host = KYTE_DB_HOST;
		}
		//
		if (\Kyte\Core\DBI::$dbUser == $username && \Kyte\Core\DBI::$dbName == $database && \Kyte\Core\DBI::$dbHost == $host) {
			return;
		}

		\Kyte\Core\DBI::setDbNameApp($database);
		\Kyte\Core\DBI::setDbUserApp($username);
		\Kyte\Core\DBI::setDbPasswordApp($password);
		\Kyte\Core\DBI::setDbHostApp($host);
		\Kyte\Core\DBI::setCharset($charset);
	}

	/**
     * Switches the database connection to the app database.
     *
     * @param bool $useApp If true, the app database will be used. Otherwise, the default database will be used.
     */
	public static function dbswitch($useApp = false) {
		\Kyte\Core\DBI::$useAppDB = $useApp;
	}

	/**
	 * Load models and controllers.
	 *
	 * This method loads both built-in and user-defined models and controllers.
	 * It imports the model files and adds them to the list of models.
	 * User overrides and changes are supported for both models and controllers.
	 *
	 * @throws \Exception If API key is not found or required.
	 *
	 * @return void
	 */
	private function loadModelsAndControllers()
	{
		// List of models
		$models = [];

		/* BUILTIN DEFINED MODELS */
		// Import builtin models first, but don't define them yet in case there are user overrides and changes
		foreach (glob(__DIR__ . "/../Mvc/Model/*.php") as $filename) {
			$model_name = basename($filename, '.php');
			require_once($filename);
			if (VERBOSE_LOG) {
				error_log("Importing builtin model $model_name...");
			}
			self::addPrimaryKey($$model_name);
			$models[$model_name] = $$model_name;
		}

		if (defined('APP_DIR') && isset($_SERVER['HTTP_X_KYTE_APPID'])) {
			$this->appId = $_SERVER['HTTP_X_KYTE_APPID'];

			// Next load user defined models and controllers (allow override of builtin)
			if (file_exists(APP_DIR . "/app/") && is_dir(APP_DIR . "/app/")) {
				/* USER DEFINED MODELS */
				// Load user defined models
				$userModelsPath = APP_DIR . "/app/models/{$this->appId}/";
				if (file_exists($userModelsPath) && is_dir($userModelsPath)) {
					foreach (glob($userModelsPath . "*.php") as $filename) {
						$model_name = basename($filename, '.php');
						if (!array_key_exists($model_name, $models)) {
							// import controller
							require_once($filename);
							if (VERBOSE_LOG) {
								error_log("Importing user defined model $model_name...");
							}
							self::addPrimaryKey($$model_name);
							self::addKyteAttributes($$model_name);
							// Add app id
							$$model_name['appId'] = $this->appId;
							// Add model to list of models
							$models[$model_name] = $$model_name;
						} else {
							// import controller
							require_once($filename);
							// User overrides are specified
							if (VERBOSE_LOG) {
								error_log("Overriding defined model $model_name...");
							}

							// Override or add attributes
							foreach ($$model_name['struct'] as $key => $value) {
								$models[$model_name]['struct'][$key] = $value;
							}
						}
					}
				}

				/* USER DEFINED CONTROLLER */
				// Load user-defined controllers
				$userControllersPath = APP_DIR . "/app/controllers/{$this->appId}/";
				if (file_exists($userControllersPath) && is_dir($userControllersPath)) {
					foreach (glob($userControllersPath . "*.php") as $filename) {
						$controller_name = basename($filename, '.php');
						// import controller
						require_once($filename);
						if (VERBOSE_LOG) {
							error_log("Checking if user defined controller has been defined..." . (class_exists($controller_name) ? 'defined!' : 'UNDEFINED!'));
						}
					}
				}
			}
		}

		// Define all models that were imported
		foreach ($models as $model_name => $model) {
			define($model['name'], $model);
		}

		// Define list of models
		if (!defined('KYTE_MODELS')) {
			define('KYTE_MODELS', $models);
		}
	}

	/**
     * Routes the API request.
     *
     * This is the main method that handles the routing of the API request.
     */
	public function route() {
		try {
			// instantiate an API key object
			$this->key = new \Kyte\Core\ModelObject(APIKey);

			// prepare response
			// return json format:
			// {
			// 	token: ‘TRANSACTION_TOKEN’,
			// 	session: ‘SESSION_TOKEN’,
			// 	error: ‘ERROR_MESSAGE’,
			// 	model: ‘MyModel’,
			// 	transaction: ‘PUT’,
			// 	txTimestamp: ‘Thu, 30 Apr 2020 07:11:46 GMT’,
			// 	data: {}
			// }
			$this->response['session'] = '0';
			$this->response['token'] = '0';	// default to public token
			$this->response['uid'] = '0';
			$now = new \DateTime();
			$now->setTimezone(new \DateTimeZone('UTC'));    // Another way
			$this->response['txTimestamp'] = $now->format('U');

			// check if request is application level
			if ($this->appId != null) {
				// retrieve application information
				$this->app = new \Kyte\Core\ModelObject(Application);
				if (!$this->app->retrieve('identifier', $this->appId)) {
					throw new \Exception("CRITICAL ERROR: Unable to find application and perform context switch for app ID {$this->appId}.");
				}
				
				self::dbappconnect($this->app->db_name, $this->app->db_username, $this->app->db_password);
			}
			
			// next determine session by checking if app requires app-level user table
			if ($this->appId != null && $this->app->user_model != null && $this->app->username_colname != null && $this->app->password_colname != null) {
				// create a session instance for in app scope
				$this->session = new \Kyte\Session\SessionManager(Session, constant($this->app->user_model), $this->app->username_colname, $this->app->password_colname, $this->appId, ALLOW_MULTILOGON, SESSION_TIMEOUT);
			} else {
				// if no app id is found, or app-level user tbl is not defined then 
				// create a session instance, and default to Kyte
				$this->session = new \Kyte\Session\SessionManager(Session, KyteUser, USERNAME_FIELD, PASSWORD_FIELD, null, ALLOW_MULTILOGON, SESSION_TIMEOUT);
			}

			$this->account = new \Kyte\Core\ModelObject(KyteAccount);
			$this->user = new \Kyte\Core\ModelObject(KyteUser);

			// if minimum count of elements exist, then process api request based on request type
			if ($this->validateRequest()) {
				if (class_exists('\\Kyte\Mvc\\Controller\\'.$this->model.'Controller')) {
					$controllerClass = '\\Kyte\Mvc\\Controller\\'.$this->model.'Controller';
				} else {
					$controllerClass = class_exists($this->model.'Controller') ? $this->model.'Controller' : '\\Kyte\\Mvc\\Controller\\ModelController';
				}
				// create new controller with model, app date format (i.e. Ymd), and new transaction token (to be verified again if private api)
				$controller = new $controllerClass(defined($this->model) ? constant($this->model) : null, $this, APP_DATE_FORMAT, $this->response);
				if (!$controller) throw new \Exception("[ERROR] Unable to create controller for model: $controllerClass.");

				switch ($this->request) {
					case 'POST':
						// post data = data
						// new  :   {data}
						$controller->new($this->data);
						break;

					case 'PUT':
						// post data = data
						// update   :   {field}, {value}, {data}
						$controller->update($this->field, $this->value, $this->data);
						break;

					case 'GET':
						// get  :   {field}, {value}
						$controller->get($this->field, $this->value);
						break;

					case 'DELETE':
						// delete   :   {field}, {value}
						$controller->delete($this->field, $this->value);
						break;
					
					default:
						throw new \Exception("[ERROR] Unknown HTTP request type: $this->request.");
						break;
				}

				// as a safety, make sure we are back on the main db
				self::dbconnect();

			} else {
				// If a post request is made to the api endpoint with no signature, identity string, or model being passed then generate a new signature based on the post data
				// format of the data being passed should be:
				// {
				//     key: ‘public_key’,
				//     identifier: ‘api_key_identifier’,
				//     token: ‘transaction_token’,
				//     time: ‘Thu, 30 Apr 2020 07:11:46 GMT’
				// }
					
				$this->generateSignature();
			}

		} catch (\Kyte\Exception\SessionException $e) {
			http_response_code(403);
			$this->response['error'] = $e->getMessage();
			$this->response = ['response_code' => 403] + $this->response;
			if (defined('LOG_RESPONSE')) {
				error_log(json_encode($this->response, JSON_PRETTY_PRINT));
			}
			echo json_encode($this->response);
			exit(0);
		} catch (\Exception $e) {
			http_response_code(400);
			$this->response = ['response_code' => 400] + $this->response;
			$this->response['error'] = $e->getMessage();
			if (defined('LOG_RESPONSE')) {
				error_log(json_encode($this->response, JSON_PRETTY_PRINT));
			}
			echo json_encode($this->response);
			exit(0);
		}

		// return pagination
		$this->response['page_size'] = $this->page_size;
		$this->response['page_total'] = $this->page_total;
		$this->response['page_num'] = $this->page_num;
		$this->response['total_count'] = $this->total_count;
		$this->response['total_filtered'] = $this->total_filtered;

		// return response data
		$this->response = ['response_code' => 200] + $this->response;
		if (defined('LOG_RESPONSE')) {
			error_log(json_encode($this->response, JSON_PRETTY_PRINT));
		}
		echo json_encode($this->response);
	}

	/**
	 * Enables Cross-Origin Resource Sharing (CORS) and returns the request method.
	 *
	 * @return string The request method.
	 */
	private function cors()
	{
		// Get the origin of the requester
		$origin = isset($_SERVER['HTTP_ORIGIN']) ? $_SERVER['HTTP_ORIGIN'] : (isset($_SERVER['HTTP_REFERER']) ? $_SERVER['HTTP_REFERER'] : $_SERVER['REMOTE_ADDR']);

		header("Access-Control-Allow-Origin: $origin");
		header('Access-Control-Allow-Credentials: true');
		header("Content-Type: application/json; charset=utf-8");

		// Get the request method
		$requestMethod = $_SERVER['REQUEST_METHOD'];

		// Access-Control headers are received during OPTIONS requests
		if ($requestMethod === 'OPTIONS') {
			// $accessControlRequestMethod = isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD']) ? $_SERVER['HTTP_ACCESS_CONTROL_REQUEST_METHOD'] : '';
			$accessControlRequestHeaders = isset($_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS']) ? $_SERVER['HTTP_ACCESS_CONTROL_REQUEST_HEADERS'] : '';

			header("Access-Control-Allow-Methods: GET, PUT, POST, DELETE, HEAD, OPTION");
			header("Access-Control-Allow-Headers: $accessControlRequestHeaders");

			exit(0);
		}

		return $requestMethod;
	}

	/**
	 * Validates the request, handles CORS, and parses the request data.
	 *
	 * @return bool True if the request is valid, false otherwise.
	 * @throws \Exception If API information for the account is not found.
	 */
	private function validateRequest()
	{
		// CORS Validation
		$this->request = $this->cors();

		$this->contentType = isset($_SERVER['CONTENT_TYPE']) ? $_SERVER['CONTENT_TYPE'] : '';

		// if content type is JSON, then parse JSON
		if (strpos($this->contentType, 'json') !== false) {
			$this->data = json_decode(file_get_contents("php://input"), true);
		} else {
			// read in data and parse into an array
			parse_str(file_get_contents("php://input"), $this->data);
		}

		if (VERBOSE_LOG > 0) {
			error_log(print_r($this->data, true));
		}

		if (IS_PRIVATE) {
			$this->signature = isset($_SERVER['HTTP_X_KYTE_SIGNATURE']) ? $_SERVER['HTTP_X_KYTE_SIGNATURE'] : null;
			if (!$this->signature) {
				return false;
			}
		}

		$this->parseIdentityString(isset($_SERVER['HTTP_X_KYTE_IDENTITY']) ? $_SERVER['HTTP_X_KYTE_IDENTITY'] : null);
		if (!$this->account) {
			return false;
		}

		// set page size
		$this->page_size = isset($_SERVER['HTTP_X_KYTE_PAGE_SIZE']) ? intval($_SERVER['HTTP_X_KYTE_PAGE_SIZE']) : PAGE_SIZE;
		// get page num from header
		$this->page_num = isset($_SERVER['HTTP_X_KYTE_PAGE_IDX']) ? intval($_SERVER['HTTP_X_KYTE_PAGE_IDX']) : 0;

		// datatables specific
		$this->response['draw'] = isset($_SERVER['HTTP_X_KYTE_DRAW']) ? intval($_SERVER['HTTP_X_KYTE_DRAW']) : 0;

		$this->response['CONTENT_TYPE'] = $this->contentType;
		$this->response['transaction'] = $this->request;
		$this->response['engine_version'] = \Kyte\Core\Version::get();

		// * URL format - root endpoint
		// https://uri-to-api-endpoint / {model} [ / {field} / {value} ]
		//
		/* parse URI        ** remember to add the following in .htaccess 'FallbackResource /index.php'
		* URL formats:
		* POST     /{model} + data
		* PUT      /{model}/{field}/{value} + data
		* GET      /{model}/{field}/{value}
		* DELETE   /{model}/{field}/{value}
		*/

		// Trim leading slash(es)
		$path = ltrim($_SERVER['REQUEST_URI'], '/');

		$elements = explode('/', $path);

		if (count($elements) >= 1) {
			$this->model = $elements[0];
			$this->field = isset($elements[1]) ? $elements[1] : null;
			$this->value = isset($elements[2]) ? urldecode($elements[2]) : null;

			$this->response['model'] = $this->model;

			// get API associated with the account
			$sub_account_api = new \Kyte\Core\ModelObject(APIKey);
			if (!$sub_account_api->retrieve('kyte_account', $this->account->id)) {
				throw new \Exception("[ERROR] Unable to find API information for the account");
			}

			// return account information in response - this is required for API handoff between the master account and subaccounts
			$this->response['kyte_api'] = API_URL;
			$this->response['kyte_pub'] = $sub_account_api->public_key;
			$this->response['kyte_num'] = $this->account->number;
			$this->response['kyte_iden'] = $sub_account_api->identifier;
			$this->response['account_id'] = $this->account->id;

			// default is always public.
			// this can be bypassed for public APIs but is highly discouraged
			if (IS_PRIVATE) {
				// VERIFY SIGNATURE
				$this->verifySignature();
			}

			return true;
		}

		return false;
	}

	/**
	 * Parses the identity string and retrieves relevant information.
	 *
	 * @param string $string The identity string to parse.
	 * @throws \Kyte\Exception\SessionException If the identity string is invalid or the API request has expired.
	 * @throws \Exception If the API key or account information is not found.
	 */
	private function parseIdentityString($string)
	{
		// Identity string format: PUBLIC_KEY%SESSION_TOKEN%DATE_TIME_GMT%ACCOUNT_NUMBER
		$identity = explode('%', base64_decode(urldecode($string)));

		if (count($identity) != 4) {
			throw new \Kyte\Exception\SessionException("[ERROR] Invalid identity string: $this->request.");
		}

		// Get UTC date from identity signature
		$this->utcDate = new \DateTime($identity[2], new \DateTimeZone('UTC'));

		// Check expiration
		if (time() > $this->utcDate->format('U') + (60 * 30)) {
			throw new \Kyte\Exception\SessionException("API request has expired.");
		}

		// Check if identity is set and retrieve API key based on the public key
		if (!isset($identity[0])) {
			throw new \Exception("API key is required.");
		}

		if (!$this->key->retrieve('public_key', $identity[0])) {
			throw new \Exception("API key not found.");
		}

		// Get account number from identity signature
		if (!$this->account->retrieve('number', $identity[3])) {
			throw new \Exception("[ERROR] Unable to find account for {$identity[3]}.");
		}

		// If 'undefined' is passed from the front end, set it to zero
		$identity[1] = $identity[1] == 'undefined' ? "0" : $identity[1];

		// Get session token from identity signature
		$this->response['session'] = $identity[1];

		// Retrieve transaction and user token corresponding to the session token
		if ($identity[1] != "0") {
			$session_ret = $this->session->validate($identity[1]);
			$this->response['session'] = $session_ret['sessionToken'];
			$this->response['token'] = $session_ret['txToken'];
			$this->response['uid'] = $session_ret['uid'];

			if (!$this->user->retrieve('id', $session_ret['uid'])) {
				throw new \Kyte\Exception\SessionException("Invalid user session.");
			}

			$this->response['name'] = $this->user->name;
			$this->response['email'] = $this->user->email;

			// Check if the user has a different account
			// Get user account
			if ($this->appId === null && $this->user->kyte_account != $this->account->id) {
				if (!$this->account->retrieve('id', $this->user->kyte_account)) {
					throw new \Exception("Unable to find account associated with the user");
				}
			}
		}
	}

	/**
	 * Verify the signature of the API response.
	 *
	 * This method verifies the signature of the API response based on the provided token, API key, and identifier.
	 * It compares the calculated signature with the provided signature and throws an exception if they don't match.
	 *
	 * @throws \Kyte\Exception\SessionException If the calculated signature does not match the provided signature.
	 */
	private function verifySignature()
	{
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


	/**
	 * Generate the signature for the API request.
	 *
	 * This method generates a signature for the API request based on the provided data.
	 * It uses HMAC-SHA256 hashing algorithm with the API key and identifier.
	 *
	 * @throws \Exception If an invalid API access key is detected.
	 */
	private function generateSignature()
	{
		if ($this->request === 'POST' && ALLOW_ENC_HANDOFF && isset($this->data['key'], $this->data['identifier'], $this->data['time'])) {
			$key = $this->data['key'];
			$identifier = $this->data['identifier'];
			$time = $this->data['time'];

			// Retrieve API key using the public_key and identifier being passed
			$obj = new \Kyte\Core\ModelObject(APIKey);
			if (!$obj->retrieve('public_key', $key, [['field' => 'identifier', 'value' => $identifier]])) {
				throw new \Exception("Invalid API access key");
			}

			// Convert date to PHP DateTime in UTC timezone
			$date = new \DateTime($time, new \DateTimeZone('UTC'));

			// Set token to zero if it's undefined from the front end
			$this->data['token'] = ($this->data['token'] === 'undefined') ? '0' : $this->data['token'];

			$hash1 = hash_hmac('SHA256', $this->data['token'], $obj->secret_key, true);
			$hash2 = hash_hmac('SHA256', $identifier, $hash1, true);
			$this->response['signature'] = hash_hmac('SHA256', $date->format('U'), $hash2);
		}
	}

}
