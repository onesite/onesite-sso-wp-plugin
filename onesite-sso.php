<?php
/*
Plugin Name: ONEsite Single Sign On
Plugin URI: http://developer.onesite.com/plugins
Description: Allow your uses to be signed into your single sign on solution.
Author: Mike Benshoof
Version: 0.1
Author URI: http://team.onesite.com/mike
License: GPL2

    Copyright 2012 ONEsite, Inc.

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2, as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/

// Include the SDK entry point.
require_once(dirname(__FILE__) . "/onesite-php-sdk/src/com/onesite/sdk.php");

// Define the ONEsite cookie values needed.
define("ONESITE_AUTH_COOKIE", "core_u");
define("ONESITE_SEC_COOKIE", "core_x");

// Force the application to run through the ONEsite SSO Initialization;
add_action('init', 'OnesiteSSO::init');

/**
 * Handles all the authentication/login flows for ONEsite Single Sign On.
 *
 * @author Mike Benshoof <mbenshoof@onesite.com>
 */
class OnesiteSSO
{
	/**
	 * The setting namespace for the admin config.
	 *
	 * @var string
	 */
	const SETTINGS_NAMESPACE = "onesite_sso_settings";
	
	/**
	 * The option prefix to prevent collisions.
	 *
	 * @var string
	 */
	const OPTION_PREFIX = "onesitesso";
	
	/**
	 * The base URI for the SSO initialization.
	 *
	 * @var string
	 */
	const REDIR_BASE = "/wp-content/plugins/onesite-sso/init";

	/**
	 * Session status check is INVALID from ONEsite.
	 *
	 * @var integer
	 */
	const ONESITE_INVALID_SESSION = 1;
	
	/**
	 * User is logged out from ONEsite, but logged in locally.
	 *
	 * @var integer
	 */
	const ONESITE_LOGGED_OUT = 2;	 

	/**
	 * The main collection of settings that drive the plugin.
	 *
	 * @var array
	 */
	public static $settings = array(
		
			"devkey" => array(
					"type"  => "string",
					"label" => "ONEsite Devkey",
					"desc"  => "Master devkey for all interaction with ONEsite.",
				),

			"networkDomain" => array(
					"type"   => "string",
					"label"  => "Master Domain",
					"desc"   => "Master domain that will maintain SSO cookies.",
				),
			
			"widgetDomain" => array(
					"type"   => "string",
					"label"  => "Widget Domain",
					"desc"   => "Domain that houses the Social Login widget.",
				),
				
			"widgetDevkey" => array(
					"type"   => "string",
					"label"  => "Widget Devkey",
					"desc"   => "Devkey to include in the Social Login widget request.",
				),

			"uniqueSiteID" => array(
					"type"   => "string",
					"label"  => "Site ID",
					"desc"   => "Unique Identifier for this site in ONEsite platform.",
				),

			"debugging" => array(
					"type"   => "bool",
					"label"  => "Enable Debugging",
					"desc"   => "Enable the system debugger.",
				),
				
			"debugDirectory" => array(
					"type"   => "string",
					"label"  => "Debugging Directory",
					"desc"   => "The relative directory that will hold the debug logs.  Should be writable by web server.",
				),	
		);
	
	/**
	 * Singleton instance of the SSO object.
	 *
	 * @var OnesiteSSO
	 */
	public static $instance = null;
	
	/**
	 * An instance of the ONEsite php SDK.
	 *
	 * @var onesite_sdk
	 */
	protected $_sdk;
	
	/**
	 * An instance of the ONEsite session API.
	 *
	 * @var onesite_sdk_api_session
	 */
	protected $_sessionApi;
	
	/**
	 * An instance of the ONEsite user API.
	 *
	 * @var onesite_sdk_api_user
	 */
	protected $_userApi;
	
	/**
	 * The localized options array.
	 *
	 * @var array
	 */
	protected $_options;
	
	/**
	 * The ONEsite session.
	 *
	 * @var onesite_sdk_dao_session
	 */
	protected $_session;
	
	/**
	 * Either load the option or parse out the domain.
	 *
	 * @var string
	 */
	protected $_cookieDomain;
	
	/**
	 * Determines if we are on an itit flow.
	 *
	 * @var boolean
	 */
	protected $_onInitFlow;
	
	/**
	 * Do we have wordpress rewrites turned on.
	 *
	 * @var boolean
	 */
	protected $_wpRewrite;
	
	/**
	 * Create an SSO object to validate the session.
	 *
	 * @return void
	 */
	public function __construct()
	{
		// Initialize some class variables;
		$this->_options = array();
		$this->_coreU = null;
		$this->_coreX = null;
		$this->_loadOptions();
		$this->_parseUrls();
		
		// We have set up a devkey, so grab an instance of the SDK.
		if(!is_null($this->devkey)) {
			$this->_sdk = new onesite_sdk($this->devkey);
			
			if ($this->debugging) {
				
				$path = dirname(__FILE__) . $this->debugDirectory;
				$this->_sdk->enableDebugging($path);				
			}
			
			$this->_sessionApi = $this->_sdk->getSessionApi();
			$this->_userApi = $this->_sdk->getUserApi();
			$this->_session = $this->_sdk->newSession();
		} else {
			$this->_sdk = null;
		}
		
		// Make sure we have a unique site ID.
		if (is_null($this->_options['uniqueSiteID'])) {
			$siteID = md5(rand(0,999999999));
			self::setOption("uniqueSiteID", $siteID);
			$this->_options['uniqueSiteID'] = $siteID;
		}
	}
	
	/**
	 * Cascade through local public, local private, and finally
	 * localized options with the magic get.
	 *
	 * @return mixed
	 */
	public function __get($key)
	{
		$pvt = "_" . $key;
		
		if (property_exists($this, $key)) {
			return $this->$key;
		} elseif (property_exists($this, $pvt)) {
			return $this->$pvt;
		} elseif (array_key_exists($key, $this->_options)) {
			return $this->_options[$key];
		} else {
			return null;
		}		
	}	
	
	/**
	 * Load all of the registered options.
	 *
	 * @return void
	 */
	protected function _loadOptions()
	{		
		foreach (self::$settings as $opt => $details) {
			$this->_options[$opt] = self::getOption($opt);
		}
	}
	
	/**
	 * Generate the cookie domain based on the URL.  Also, determine
	 * if we are on a keymaster flow.
	 *
	 * @return void
	 */
	protected function _parseUrls()
	{
		// Determine the cookie name based on the base domain.
		$dom_parts = explode(".", $_SERVER['HTTP_HOST']);
		$tld = array_pop($dom_parts);
		$base = array_pop($dom_parts);		
		$this->_cookieDomain = "$base.$tld";

		$rewrite = new WP_Rewrite();
		$this->_wpRewrite = $rewrite->using_mod_rewrite_permalinks();

		// See if we should change logic if we are on an init flow.
		if ($this->_wpRewrite) {
		
			if (strpos($_SERVER['REQUEST_URI'], self::REDIR_BASE) === 0) {
				$this->_onInitFlow = true;
			} else {
				$this->_onInitFlow = false;
			}
		} else {
			
			if (array_key_exists("ssoinit", $_GET) && $_GET['ssoinit'] == 1) {
				$this->_onInitFlow = true;
			} else {
				$this->_onInitFlow = false;
			}
		}
	}

	/**
	 * Run all page hits through this flow to determine integration points
	 * with ONEsite.  Launch any redirects, handle any cookie auth, etc from
	 * here.
	 *
	 * @return void
	 */
	public static function init()
	{
		// By default, always add the admin panel.
		add_action('admin_menu', 'OnesiteSSO::adminPanel');
		
		// Grab a new class and store an instance of it
		$class = __CLASS__;
		$sso = new $class();
		self::$instance = $sso;

		// No devkey has been defined (or we don't have an SDK).
		if(is_null($sso->sdk) || $sso->devkey == "") {
			$sso->initialSetup();
			return;
		}		

		// Make sure we have cookies from parent before we try anything crazy.
		try {
			$sso->validateMasterSession();
		} catch (onesite_exception $e) {
			
			// Go through the redirect channels and start a session.
			$sso->initMasterSession();
			return;
		}
		
		// Overtake the login form and capture logout.
		add_action('login_head','OnesiteSSO::overwriteLoginPage');
		add_action('wp_logout', 'OnesiteSSO::handleLogout');
		
		// Handle the flow as needed.
		$sso->handleSeamless();		
	}

	/**
	 * When setting up the plugin for the first time, this will attempt
	 * to validate your devkey, auto populate the other needed fields, 
	 * and mark your current logged in user as a temporary option.  You
	 * will be able to work in the admin panel and front end site as your
	 * current user without any additional login flows until first logout
	 * from Wordpress or first login on federated site.
	 *
	 * @return void
	 */
	public function initialSetup()
	{
		// Not an administrator - so nothing to set up.
		if (!is_admin()) {			
			return;
		}		
		
		// Just hitting an admin page for the first time
		if ($_POST['action'] != "update") {
			add_action('admin_notices', 'OnesiteSSO::adminDevkeyMissing');
			return;
		}
		
		// They are not trying to set up the SSO plugin, so nothing to do.
		if (!array_key_exists("onesitesso_devkey", $_POST)) {
			return;
		}
		
		// Try to make an instance of the SDK and validate the key.
		$sdk = new onesite_sdk($_POST['onesitesso_devkey']);
		$sdk->enableDebugging(dirname(__FILE__) . "/logs");
		$info = $sdk->getIntegrationInfo();
		
		// The devkey isn't valid, so just break out.
		if ($info === false) {
			add_action('admin_notices', 'OnesiteSSO::adminDevkeyWrong');
			return;
		}
		
		// Check to see if the user is logged in.
		if(is_user_logged_in()) {
			
			global $current_user;
			get_currentuserinfo();
			
			// Try to link the accounts.
			$extAcct = $sdk->newExternalAccount();
			$extAcct->providerName = "wordpress-" . $this->uniqueSiteID;
			$extAcct->userIdentifier = $current_user->ID;
			
			$user = $sdk->newUser();
			$user->id = $info['admin_user_id'];
			
			$sdk->getUserApi()->addExternalAccount($user, $extAcct);
				
			// Manually update the POST variables to update the options.
			$_POST["onesitesso_networkDomain"] = $info['domain'];
			$_POST["onesitesso_widgetDomain"] = "widgets." . $info['domain'];
			$_POST["onesitesso_widgetDevkey"] = $info['widget_devkeys'][0]['devkey'];
			$_POST["onesitesso_uniqueSiteID"] = $this->uniqueSiteID;
			$_POST["onesitesso_debugging"] = 0;
			$_POST["onesitesso_debugDirectory"] = "";
			
			self::setOption("wpAdminId", $current_user->ID);
		}

		return;
	}
	
	/**
	 * Make sure that we have cookies stored on the master auth node
	 * to allow for federation.  What is done with those cookies is
	 * dependent on plugin options.
	 *
	 * @return void
	 */
	public function validateMasterSession()
	{
		// We are on the init flow, so store the cookies and redirect.
		if ($this->_onInitFlow) {
			
			// Keymaster redirect flow.
			if (array_key_exists("oned", $_GET)) {
				
				$tmp_parts = explode(',', base64_decode($_GET['oned']));							
				$parts = array();
				foreach ($tmp_parts as $tmp_part) {
					$tmp_part_parts = explode('=', $tmp_part);
					$parts[$tmp_part_parts[0]] = $tmp_part_parts[1];
				}

				if (empty($parts['core_u'])) {
					onesite_sdk::debugLog("Missing a coreU on an itit flow where oned GET present.");
					return;
				}
				
				$cu = $parts['core_u'];
				$cx = $parts['core_x'];
				
			}
			// Social login flow.
			elseif (array_key_exists("core_u", $_GET)) {
				
				$cu = $_GET['core_u'];
				$cx = $_GET['core_x'];
				
			} else {
				onesite_sdk::debugLog("Missing a coreU on an itit flow entirely.");				
				return;
			}
			
			// Localize the SSO cookie to this domain.
			$this->storeLocalCookie(ONESITE_AUTH_COOKIE, $cu);
			$this->storeLocalCookie(ONESITE_SEC_COOKIE, $cx);
			
			if (array_key_exists('org', $_GET)) {
				$loc = base64_decode($_GET['org']);
			} else {
				$loc = "/";
			}
			onesite_sdk::debugLog("Doing a redirect in validate session " . $loc);
			wp_redirect($loc);
			exit;
		}
		
		// Try to grab local core_u/core_x.
		$this->_session->coreU = $this->checkLocalCookie(ONESITE_AUTH_COOKIE);
		$this->_session->coreX = $this->checkLocalCookie(ONESITE_SEC_COOKIE);
		
		if (is_null($this->_session->coreU) || is_null($this->_session->coreX)) {
			throw new onesite_exception();
		}
	}
	
	/**
	 * Make SDK calls to ONEsite to begin the federated SSO cookie
	 * transfer. This will trigger a redirect flow that will result 
	 * with cookies being present.
	 *
	 * @return void
	 */
	public function initMasterSession()
	{
		// Determine the rewrite logic.
		if ($this->_wpRewrite) {
		
			// Rewriting enabled, so redirect to a clean URL.
			$redirect_url = site_url(OnesiteSSO::REDIR_BASE);
			$redirect_url .= '?org=' . base64_encode($_SERVER['REQUEST_URI']);
		} else {

			// Rewriting disabled, so set add some GET vars.
			$redirect_url = self::cleanCurUrl();
			$qs = 'ssoinit=1&org=' . base64_encode($_SERVER['REQUEST_URI']);

			if ($_SERVER['QUERY_STRING'] != "") {
				$redirect_url .= "&$qs";
			} else {
				$redirect_url .= "?$qs";
			}			
		}

		// Make the SDK call to get the appropriate redirect URL.
		$loc = $this->_sessionApi->joinCrossDomain(
			$redirect_url,
			$this->networkDomain
		);

		wp_redirect($loc);
		exit;
	}

	/**
	 * Static entry point to trigger the session logout call from
	 * the SDK.
	 *
	 * @return void
	 */
	public static function handleLogout()
	{
		// Grab the instance of this class.		
		$sso = self::$instance;
		$sso->doLogout();
	}
	
	/**
	 * They have seamless SSO enabled, so make the keymaster checks,
	 * login if needed, etc.
	 *
	 * @return void
	 */
	public function handleSeamless()
	{
		onesite_sdk::debugLog("Go through seamless flow");
	
		try {
			
			// Throws exception on invalid ONEsite login state.
			global $current_user;
			get_currentuserinfo();
			
			if ($current_user->ID != self::getOption("wpAdminId")) {			
				// Not in setup flow - run normal session check.
				$this->_sessionCheck();
			} else {
				// Call a session check from the API.
				$this->_sessionApi->check($this->_session);
				$info = $this->_sdk->getIntegrationInfo();
	
				// No user at all - so bail at this point.
				if (is_null($this->_session->user)) {
					return;
				}
	
				if ($this->_session->user->id == $info['admin_user_id']) {
					// We are properly logged in on the keymaster.
					delete_option("onesitesso_wpAdminId");
				} else {
					// We aren't logged into keymaster, so fake it.
					$this->_session->user->id = $info['admin_user_id'];
				}				
			}

			// Check for a linked wordpress account identifier.
			$extAcct = $this->_sdk->newExternalAccount();
			$extAcct->providerName = "wordpress-" . $this->uniqueSiteID;
			$this->_userApi->getExternalAccount($this->_session->user, $extAcct);
			$wp_uid = $extAcct->userIdentifier;

			// Account is not linked - so handle that.
			if (is_null($wp_uid)) {
				$this->_notFoundRemotely($extAcct);
			} else {
				$this->_foundRemotely($wp_uid);
			}

		} catch (Exception $e) {
			$this->_handleException($e);			
		}
	}
	
	/**
	 * Run the ONEsite SSO logout.
	 *
	 * @return void
	 */
	public function doLogout()
	{
		global $current_user;
		get_currentuserinfo();
		
		if ($current_user->ID == self::getOption("wpAdminId")) {
			delete_option("onesitesso_wpAdminId");
		}
		
		onesite_sdk::debugLog("Initiating SDK logout");
		$this->_sessionApi->logout($this->_session);
		wp_redirect(home_url());
		exit;
	}
	
	/**
	 * Check to see if the user has a valid SSO session with ONEsite. If 
	 * ONEsite session is invalid or user is logged out of ONEsite and logged in 
	 * locally, then throw an exception.
	 *
	 * @return void
	 */
	protected function _sessionCheck()
	{
		// Call a session check from the API.
		$this->_sessionApi->check($this->_session);
		
		// Is session no longer valid?
		if (!$this->_session->isValid()) {
			
			throw new onesite_exception(
					"Invalid ONEsite session detected.",
					self::ONESITE_INVALID_SESSION
				);
		}
		// Is user logged out on ONEsite but logged in locally?
		else if ($this->_session->isAnonymous() && is_user_logged_in()) {
			
			throw new onesite_exception(
					"Logged out at ONEsite, but logged in locally.",
					self::ONESITE_LOGGED_OUT
				);
		}
	}
	
	/**
	 * The user had a valid WP ID in remote ONEsite store.  So
	 * make sure they are the correct user and log them in or
	 * do nothing if they are already logged in.
	 *
	 * @param integer $wp_uid
	 *
	 * @return void
	 */
	protected function _foundRemotely($wp_uid)
	{
		$user_info = get_userdata($wp_uid);
		
		// Check to see if the user is logged in.
		if(is_user_logged_in()) {
			
			onesite_sdk::debugLog("We have a logged in user - so validate");
			
			global $current_user;
			get_currentuserinfo();
			
			// User is logged in and IDs match up, so nothing to do.
			if($current_user->ID == $wp_uid) {
				onesite_sdk::debugLog("Valid user, so nothing to do.");
				return;
			} else {
				
				onesite_sdk::debugLog("We are logged in as the wrong user.");
				wp_set_auth_cookie($wp_uid, true, false);
				do_action('wp_login', $user_info->user_login);
				wp_redirect( $_SERVER['REQUEST_URI'] );
				exit;				
			}
		} else {

			// We found a matching ID, so log the user in.
			if($user_info->ID == $wp_uid) {

				onesite_sdk::debugLog("We are not logged in, but have a valid WP ID.");

				wp_set_auth_cookie($wp_uid, true, false);
				do_action('wp_login', $user_info->user_login);
				wp_redirect( $_SERVER['REQUEST_URI'] );
				exit;

			} else {
				
				onesite_sdk::debugLog("Log that we reached a very odd state for WP->ID {$wp_uid}.");
				return;
			}
		}

		return true;
	}
	
	/**
	 * The user ID was not found in the remote ONEsite SSO data store.  So
	 * handle that accordingly.  This should react according to defined options.
	 *
	 * @param onesite_sdk_dao_externalAccount $acct
	 *
	 * @return void
	 */
	protected function _notFoundRemotely($extAcct)
	{
		onesite_sdk::debugLog("WP-ID not found at ONEsite for {$this->_session->user->id}, so store it.");
		$local_user = get_user_by_email(trim($this->_session->user->email));

		if ($local_user === false) {
			
			onesite_sdk::debugLog("Local user not found.");
			
			// Find available username.
			$new_name = false;
			$loop = 0;
			while ($loop < 20) {
				$tmp_name = $this->_session->user->username;
				if ($loop > 0) {
					$tmp_name .= $loop;
				}

				$user_exists = username_exists($tmp_name);
				if (!$user_exists) {
					$new_name = $tmp_name;
					break;
				}

				$loop++;
			}
			if (!$new_name) {
				return;
			}
			
			// Create a user with a random password.
			$random_password = wp_generate_password( 12, false );
			$wp_uid = wp_create_user( 
				$new_name,
				$random_password,
				$this->_session->user->email
			);
			
			onesite_sdk::debugLog("Local user $new_name stored - $wp_uid is new UID.");
			
		} else {
			$wp_uid = $local_user->ID;
			$new_name = $local_user->user_login;
		}		
		
		// Store the WP user_id as ONEsite user property.
		$extAcct->userIdentifier = $wp_uid;
		$this->_userApi->addExternalAccount(
				$this->_session->user,
				$extAcct
			);
		
		// Log the user into wordpress.
		wp_set_auth_cookie($wp_uid, true, false);
		do_action('wp_login', $new_name);
		wp_redirect( $_SERVER['REQUEST_URI'] );
		exit;
	}

	/**
	 * Store a cookie local to this domain.
	 *
	 * @param string  $name    The name of the cookie
	 * @param string  $value   The value stored in the cookie
	 * @param integer $expires Seconds until expiration (default 2 weeks)
	 *
	 * @return boolean
	 */
	public function storeLocalCookie($name, $value, $expires = 1209600)
	{
		setcookie($name, $value, time()+$expires, "/", $this->_cookieDomain);
	}
	
	/**
	 * Check for the value of a cookie locally.
	 *
	 * @param string $name
	 *
	 * @return mixed
	 */
	public function checkLocalCookie($name)
	{
		if (array_key_exists($name, $_COOKIE)) {
			return $_COOKIE[$name];
		} else {
			return null;
		}
	}

	/**
	 * A wrapper that adds the proper prefix, etc and fetches the option from
	 * the underlying wordpress option system.
	 *
	 * @param string $opt
	 *
	 * @return mixed
	 */
	public static function getOption($opt)
	{
		$key = self::OPTION_PREFIX . "_" . $opt;
		return get_option($key, null);
	}
	
	/**
	 * Overwrite any option that is currently set.
	 *
	 * @param string $opt The option name
	 * @param string $val The option value
	 *
	 * @return boolean
	 */
	public static function setOption($opt, $val)
	{
		$key = self::OPTION_PREFIX . "_" . $opt;
		add_option($key);
		return update_option($key, $val);
	}
	
	/**
	 * Handle any session checking exceptions.
	 *
	 * @param Exception $e
	 *
	 * @return mixed
	 */
	protected function _handleException($e)
	{
		switch ($e->getCode()) {
			
			case self::ONESITE_INVALID_SESSION:
			case self::ONESITE_LOGGED_OUT:
				// Log them out locally if needed.
				if (is_user_logged_in()) {
					wp_logout();
				}		
				break;
			
			default:
				onesite_sdk::debugLog("Unknown exception caught");
				return;
		}
		
		// Delete any ONEsite cookies.
		$this->storeLocalCookie(ONESITE_AUTH_COOKIE, "", -3600);
		$this->storeLocalCookie(ONESITE_SEC_COOKIE, "", -3600);
		wp_redirect( $_SERVER['REQUEST_URI'] );
		exit;		
	}
	
	/**
	 * Display the social login widget.  This is normally handled from within
	 * the footer as this is a modal.
	 *
	 * @param boolean $force
	 *
	 * @return false
	 */
	public static function printSocialLogin()
	{		
		$devkey = self::getOption('widgetDevkey');
		$networkDom = self::getOption('networkDomain');
		$widgetDom = self::getOption('widgetDomain');

		$path = "/wp-content/plugins/onesite-sso";
		$callback_url = $path.'/connection.html';

		$rewrite = new WP_Rewrite();

		// Determine the rewrite logic.
		if ($rewrite->using_mod_rewrite_permalinks()) {
		
			// Rewriting enabled, so redirect to a clean URL.
			$redirect_url = site_url(OnesiteSSO::REDIR_BASE);
						
			if (wp_get_referer()) {
				$redirect_url .= '?org=' . base64_encode(wp_get_referer());
			} else {
				$redirect_url .= '?';
			}
			
		} else {

			// Rewriting disabled, so set add some GET vars.
			$redirect_url = self::cleanCurUrl();
			$qs = 'ssoinit=1';

			if (wp_get_referer()) {
				$qs .= '&org=' . base64_encode(wp_get_referer());
			}

			if ($_SERVER['QUERY_STRING'] != "") {
				$redirect_url .= "&$qs";
			} else {
				$redirect_url .= "?$qs";
			}			
		}


		$widget = <<<WIDGET
<script type='text/javascript' src='http://ajax.googleapis.com/ajax/libs/jquery/1.7.1/jquery.min.js'></script>
<script type="text/javascript">

		document.write(
				'<script type="text/javascript" src="'
				+ 'http://{$widgetDom}/js/socialLogin/display'
				+ '?one_widget_node={$networkDom}'
				+ '&devkey={$devkey}'
				+ '&callback_url={$callback_url}'
				+ '&load_profile=true'
				+ '&js_callback=onesitesso_callback'
				+ '&view=modal'
				+ '"><' + '/script>'
		);

		function onesitesso_callback(action, args) {
				switch (action) {
						case 'loaded':
						case 'error':
								return false;
				}

				var redirect_url = '{$redirect_url}';
				for (x in args) {
						redirect_url += '&' + x + '=' + encodeURIComponent(args[x]);
				}

				window.location.assign(redirect_url);
				return false;
		}

</script>
WIDGET;

		echo $widget;
	}

	/**
	 * Strip out the native login form and replace with social login.
	 * When the dom is ready, automatically display the modal
	 *
	 * @return void
	 */
	public static function overwriteLoginPage()
	{
		self::printSocialLogin();
		
		echo "	<script type='text/javascript'>
					$(function() {
					 	// Handler for .ready() called.
					 	document.getElementById('login').innerHTML = '';
					 	oneSocialLogin.init();
					});						
				</script>";
	}

	/**
	 * Generate the wp-admin plugin management page.
	 *
	 * @return void
	 */
	public static function adminPanel()
	{
		add_options_page(
				'ONEsite SSO Configuration',
				'ONEsite SSO',
				'manage_options',
				self::SETTINGS_NAMESPACE,
				'OnesiteSSO::showOptions'
			);
		add_action('admin_init', 'OnesiteSSO::registerSettings');
	}

	/**
	 * Register the WP Plugin settings.
	 *
	 * @return void
	 */
	public static function registerSettings()
	{
		foreach (self::$settings as $opt => $details) {
			register_setting(self::SETTINGS_NAMESPACE, self::OPTION_PREFIX . "_" . $opt);
		}
	}

	/**
	 * Print out the option form.  Fetch the stored options (if any) and
	 * prepopulate the form.
	 *
	 * @return void
	 */
	public static function showOptions()
	{
		// Capture the output of the settings_fields nonce.	
		ob_start();
		settings_fields( self::SETTINGS_NAMESPACE );
		$settings_fields = ob_get_clean();
	
		// Build the main table.
		$pre = "<div class=\"wrap\">
					<h2>" . translate('ONEsite SSO') . "</h2>
					<form method=\"post\" action=\"options.php\">"
						. $settings_fields .

						"<table class=\"form-table\">";
						
		$end = "		</table>
						<p class=\"submit\">
						<input type=\"submit\" class=\"button-primary\" value=\"" . translate('Save Changes') ."\" />
						</p>
					</form>
				</div>";
		
		
		$devkey = self::getOption("devkey");
		
		if (is_null($devkey) || $devkey == "") {
			$raw_rows = self::_fetchSetupOptions();			
		} else {
			$raw_rows = self::_fetchFullOptions();
		}
		echo $pre . implode("\n", $raw_rows) . $end;
	}

	/**
	 * Just display the devkey input box for initial plugin setup.
	 *
	 * @return array
	 */
	protected static function _fetchSetupOptions()
	{		
		return array(
				"<tr valign=\"top\">
					<th scope=\"row\">ONEsite Devkey: <a href=\"javascript:alert('Master devkey for all interaction with ONEsite.')\"><img src=\"/wp-admin/images/comment-grey-bubble.png\"></a></th>
					<td><input name=\"onesitesso_devkey\" value=\"\" type=\"text\"></td>
				</tr>",
			);
	}
	
	/**
	 * Get the full set of options for plugin setup.
	 *
	 * @return array
	 */
	protected static function _fetchFullOptions()
	{
		$raw_rows = array();
	
		// Build all the rows based on the settings fields above.
		foreach (self::$settings as $opt => $details) {
		
			$row = "	<tr valign=\"top\">
							<th scope=\"row\">" . translate($details['label']) . ": <a href=\"javascript:alert('" .
							translate($details['desc']);
			
			if (array_key_exists("parent", $details)) {
				$row .= " (Requires " . self::$settings[$details['parent']]['label'] . " to be enabled.)";
			}			
			
			$row .=	 "')\"><img src=\"/wp-admin/images/comment-grey-bubble.png\"></a></th>
							<td>";
						
			switch ($details['type']) {
				
				case "bool":
					
					$val = (int)self::getOption($opt);
					
					if ($val === 0) {
						$row .= "<input 
									type=\"radio\" 
									name=\"" . self::OPTION_PREFIX . "_" . $opt . "\"
									value=\"0\" checked>No
								 <input 
									type=\"radio\" 
									name=\"" . self::OPTION_PREFIX . "_" . $opt . "\"
									value=\"1\">Yes";						
					} else {
						$row .= "<input 
									type=\"radio\" 
									name=\"" . self::OPTION_PREFIX . "_" . $opt . "\"
									value=\"0\">No
								 <input 
									type=\"radio\" 
									name=\"" . self::OPTION_PREFIX . "_" . $opt . "\"
									value=\"1\" checked>Yes";							
					}		
					break;
				
				case "string":
				case "int":
				default:
				
					$row .= "<input 
								type=\"text\" 
								name=\"" . self::OPTION_PREFIX . "_" . $opt . "\" 
								value=\"" . self::getOption($opt) . "\" />";
					break;
			}

			$row .= 		"</td>
						</tr>";
						
			$raw_rows[] = $row;
		}
		
		return $raw_rows;
	}
	
	/**
	 * Alert the user that they don't have a devkey setup.
	 *
	 * @return void
	 */
	public static function adminDevkeyMissing()
	{
		ob_start();
		printf( 
			__( 'ONEsite SSO plugin almost ready to configure. To start using ONEsite SSO <strong>you need to set your ONEsite SDK Devkey</strong>. You can do that in the <a href="%1s">ONEsite SSO settings page</a>.', 'wpsc' ),
			admin_url( 'options-general.php?page=' . self::SETTINGS_NAMESPACE ) 
		);
		$msg = ob_get_clean();
		
		echo "	<div class=\"error\">
					<p>$msg</p>
				</div>";		
	}
	
	/**
	 * Alert the user that they don't have a devkey setup.
	 *
	 * @return void
	 */
	public static function adminDevkeyWrong()
	{
		ob_start();
		printf( 
			__( '<strong>Invalid ONEsite SDK Devkey detected.</strong>. Please update the devkey in the <a href="%1s">ONEsite SSO settings page</a>.', 'wpsc' ),
			admin_url( 'options-general.php?page=' . self::SETTINGS_NAMESPACE ) 
		);
		$msg = ob_get_clean();
		
		echo "	<div class=\"error\">
					<p>$msg</p>
				</div>";		
	}
	
	/**
	 * Handle the case where wordpress is installed in a subdirectory.
	 *
	 * @return string
	 */
	public static function cleanCurUrl()
	{
		$parts = parse_url(home_url());
		return home_url(
			str_replace(
				$parts['path'],
				"",
				$_SERVER['REQUEST_URI']
			)
		);
	}
}
