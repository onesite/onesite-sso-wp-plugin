<?php
/*
Plugin Name: ONEsite Single Sign On
Plugin URI: http://developer.onesite.com/plugins
Description: Allows your users to be logged into your site using the ONESite single sign-on solution.
Author: ONEsite
Author URI: http://onesite.com
Version: 1.0
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
require_once dirname(__FILE__) . "/onesite-php-sdk/src/com/onesite/sdk.php";

// Define the ONEsite cookie values needed.
define("ONESITE_AUTH_COOKIE", "core_u");
define("ONESITE_SEC_COOKIE", "core_x");

// Force the application to run through the ONEsite SSO Initialization;
add_action('init', 'OnesiteSSO::init');

/**
 * Handles all the authentication/login flows for ONEsite Single Sign On.
 *
 * @author Derek Myers <dmyers@onesite.com>
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
	const REDIR_BASE = "/wp-content/plugins/%s/init";

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
		"uniqueSiteID" => array(
			"type"   => "string",
			"label"  => "Site ID",
			"desc"   => "Unique Identifier for this site in ONEsite platform.",
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
		"debugging" => array(
			"type"   => "bool",
			"label"  => "Enable Debugging",
			"desc"   => "Enable the system debugger.",
		),
		"debugDirectory" => array(
			"type"   => "string",
			"label"  => "Debugging Directory",
			"desc"   => "The relative directory that will hold the debug logs.",
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
	 * Determines if we are on an init flow.
	 *
	 * @var boolean
	 */
	protected $_onInitFlow = false;
	
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
				$path = dirname(__FILE__) . '/' . $this->debugDirectory;
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
		
		$pluginDir = self::getPluginDir();
		$redirBase = sprintf(self::REDIR_BASE, $pluginDir);

		// See if we should change logic if we are on an init flow.
		if ($this->_wpRewrite) {
			if (strpos($_SERVER['REQUEST_URI'], $redirBase) === 0) {
				$this->_onInitFlow = true;
			}
		} else {
			if (array_key_exists("ssoinit", $_GET) && $_GET['ssoinit'] == 1) {
				$this->_onInitFlow = true;
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
		onesite_sdk::debugLog("Go through init.");

		// Add the admin panel.
		add_action('admin_menu', 'OnesiteSSO::adminPanel');
		
		// Register settings.
		add_action('admin_init', 'OnesiteSSO::registerSettings');
		
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
		}
		
		// Overtake the login form.
		add_action('login_head','OnesiteSSO::overwriteLoginPage');
		
		// Capture logout.
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
		
		// Just hitting an admin page for the first time.
		if (isset($_POST['action']) && $_POST['action'] != "update") {
			add_action('admin_notices', 'OnesiteSSO::adminDevkeyMissing');
			return;
		}
		
		// They are not trying to set up the SSO plugin, so nothing to do.
		if (!array_key_exists("onesitesso_devkey", $_POST)) {
			return;
		}
		
		// Try to make an instance of the SDK and validate the key.
		$_POST['onesitesso_devkey'] = trim($_POST['onesitesso_devkey']);
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
			onesite_sdk::debugLog("Starting the session init flow.");
			
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
		onesite_sdk::debugLog("Go through master session.");
		
		$pluginDir = self::getPluginDir();
		$redirBase = sprintf(self::REDIR_BASE, $pluginDir);

		// Determine the rewrite logic.
		if ($this->_wpRewrite) {
			// Rewriting enabled, so redirect to a clean URL.
			$redirect_url = site_url($redirBase);
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

		onesite_sdk::debugLog("Redirect back to " . $redirect_url);
		onesite_sdk::debugLog("Our network domain " . $this->networkDomain);

		// Make the SDK call to get the appropriate redirect URL.
		$loc = $this->_sessionApi->joinCrossDomain(
			$redirect_url,
			$this->networkDomain
		);

		onesite_sdk::debugLog("Doing a redirect in master session " . $loc);
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
			
			onesite_sdk::debugLog("Current WP ID ({$current_user->ID}).");
			
			if (!self::getOption("wpAdminId") || $current_user->ID != self::getOption("wpAdminId")) {
				onesite_sdk::debugLog("Go through non-setup flow.");
				
				// Not in setup flow - run normal session check.
				$this->_sessionCheck();
			} else {
				onesite_sdk::debugLog("Go through setup flow.");

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
			
			onesite_sdk::debugLog("Current Site ID ({$this->uniqueSiteID}).");

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

		$redirect = home_url();
		onesite_sdk::debugLog("Doing a redirect in logout " . $redirect);
		wp_redirect($redirect);
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
		onesite_sdk::debugLog("Go through session check");

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
		onesite_sdk::debugLog("WP-ID found at ONEsite for {$this->_session->user->id}, so log them in.");

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
				onesite_sdk::debugLog("Logging in WP ID - {$user_info->user_login}.");

				wp_set_auth_cookie($wp_uid, true, false);
				do_action('wp_login', $user_info->user_login);

				onesite_sdk::debugLog("Doing a redirect in found remote " . $_SERVER['REQUEST_URI']);
				wp_redirect( $_SERVER['REQUEST_URI'] );
				exit;				
			}
		} else {
			// We found a matching ID, so log the user in.
			if($user_info->ID == $wp_uid) {
				onesite_sdk::debugLog("We are not logged in, but have a valid WP ID.");
				onesite_sdk::debugLog("Logging in WP ID - {$user_info->user_login}.");

				wp_set_auth_cookie($wp_uid, true, false);
				do_action('wp_login', $user_info->user_login);

				onesite_sdk::debugLog("Doing a redirect in found remote " . $_SERVER['REQUEST_URI']);
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
		if (!empty($this->_session->user->id)) {
			onesite_sdk::debugLog("WP-ID not found at ONEsite for {$this->_session->user->id}, so store it.");
		}
		
		$local_user = false;
		if (!empty($this->_session->user->email)) {
			$local_user = get_user_by_email(trim($this->_session->user->email));
		}

		if ($local_user === false) {
			onesite_sdk::debugLog("Local user not found.");

			$new_registrations = get_option('users_can_register');
			if (!$new_registrations) {
				onesite_sdk::debugLog("New user registrations disabled.");
				return;
			}
			
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

			onesite_sdk::debugLog("Creating a new local user.");
			
			// Create a user with a random password.
			$random_password = wp_generate_password( 12, false );
			$wp_uid = wp_create_user( 
				$new_name,
				$random_password,
				$this->_session->user->email
			);
			
			onesite_sdk::debugLog("Local user $new_name created - $wp_uid is new UID.");
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

		onesite_sdk::debugLog("Logging in WP ID - $wp_uid.");
		
		// Log the user into wordpress.
		wp_set_auth_cookie($wp_uid, true, false);
		do_action('wp_login', $new_name);

		onesite_sdk::debugLog("Doing a redirect in not found remote " . $_SERVER['REQUEST_URI']);
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
	 * Returns the plugin's directory name.
	 *
	 * @return string
	 */
	public static function getPluginDir()
	{
		return dirname( plugin_basename( __FILE__ ) );
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

		onesite_sdk::debugLog("Doing a redirect in handle exception " . $_SERVER['REQUEST_URI']);
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
		wp_enqueue_style( 'onesite_sso', plugins_url( 'style/style.css', __FILE__), array(), '1.0' );
		
		wp_enqueue_script( 'jquery' );
		
		$devkey = self::getOption('widgetDevkey');
		$networkDom = self::getOption('networkDomain');
		$widgetDom = self::getOption('widgetDomain');
		$pluginDir = self::getPluginDir();

		$path = site_url('/wp-content/plugins/' . $pluginDir);
		$callback_url = $path . '/connection.html';

		$rewrite = new WP_Rewrite();
		$redirBase = sprintf(self::REDIR_BASE, $pluginDir);

		// Determine the rewrite logic.
		if ($rewrite->using_mod_rewrite_permalinks()) {
			// Rewriting enabled, so redirect to a clean URL.
			$redirect_url = site_url($redirBase);
						
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
		?>
<script type="text/javascript">
	document.write(
		'<script type="text/javascript" src="'
		+ 'http://<?php echo $widgetDom ?>/js/socialLogin/display'
		+ '?one_widget_node=<?php echo $networkDom ?>'
		+ '&devkey=<?php echo $devkey ?>'
		+ '&callback_url=<?php echo $callback_url ?>'
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

		var redirect_url = '<?php echo $redirect_url ?>';
		for (x in args) {
			redirect_url += '&' + x + '=' + encodeURIComponent(args[x]);
		}

		window.location.assign(redirect_url);
		return false;
	}
</script>
		<?php
	}

	/**
	 * Strip out the native login form and replace with social login.
	 * When the dom is ready, automatically display the modal.
	 *
	 * @return void
	 */
	public static function overwriteLoginPage()
	{
		if (is_user_logged_in()) {
			$redirect = home_url();
			onesite_sdk::debugLog("User is already logged in.");
			onesite_sdk::debugLog("Doing a redirect in login " . $redirect);
			wp_redirect($redirect);
			exit;
		}
		
		self::printSocialLogin();
		?>
<script type="text/javascript">
jQuery(function() {
	// Handler for .ready() called.
	oneSocialLogin.init();
});						
</script>
		<?php
	}

	/**
	 * Generate the wp-admin plugin management page.
	 *
	 * @return void
	 */
	public static function adminPanel()
	{
		add_menu_page(
			__('ONEsite SSO', 'onesite'),
			__('ONEsite SSO', 'onesite'),
			'manage_options',
			self::SETTINGS_NAMESPACE,
			'OnesiteSSO::showOptions'
		);
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
		wp_enqueue_style( 'onesite_sso_admin', plugins_url( 'style/style-admin.css', __FILE__), array(), '1.0' );
		
		$devkey = self::getOption("devkey");
		
		if (is_null($devkey) || $devkey == "") {
			$raw_rows = self::_fetchSetupOptions();			
		} else {
			$raw_rows = self::_fetchFullOptions();
		}
		?>
		<div class="wrap">
			<div class="onesite-logo"></div>
			
			<h2><?php echo __('Single Sign-On', 'onesite'); ?></h2>
			
			<h3><?php echo __('Settings', 'onesite'); ?></h3>
			
			<?php settings_errors(); ?>
			
			<form method="post" action="options.php">
				<?php settings_fields( self::SETTINGS_NAMESPACE ); ?>

				<table class="form-table">
					<?php echo implode("\n", $raw_rows); ?>
				</table>
				
				<?php submit_button(); ?>
			</form>
		</div>
		<?php
		
		if (is_null($devkey) || $devkey == "") {
			echo "<strong>or</strong><br />
				<div id=\"oneSsoSignup\" style=\"width: 500px\"></div>
				<script type=\"text/javascript\">
					if (typeof ONELOADER == 'undefined' || !ONELOADER) {
						ONELOADER = new Array();
						(function() {
							var e = document.createElement('script'); e.type = 'text/javascript'; e.async = true;
							e.src = 'http://images.onesite.com/resources/scripts/utils/widget.js?ver=1';
							(document.getElementsByTagName('head')[0] || document.getElementsByTagName('body')[0]).appendChild(e);
						}());
					}
					ONELOADER.push(function () {
						ONESITE.Widget.load('oneSsoSignup', 'node/ssoSignup', {
							one_widget_node   : 'onesite.com',
							hidePricelist     : 1
						});
					});
				</script>";
		}
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
				<th scope=\"row\"><label for=\"onesitesso_devkey\">Enter ONEsite Devkey</label></th>
				<td>
					<input type=\"text\" name=\"onesitesso_devkey\" id=\"onesitesso_devkey\" />
					<p class=\"description\">Master devkey for all interaction with ONEsite.</p>
				</td>
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
							<th scope=\"row\"><label for=\"".$opt."\">" . __($details['label'], 'onesite') . "</label>";
			
			if (array_key_exists("parent", $details)) {
				$row .= " (Requires " . self::$settings[$details['parent']]['label'] . " to be enabled.)";
			}			
			
			$row .=	 "</th>
							<td><input id=\"".$opt."\"
										name=\"" . self::OPTION_PREFIX . "_" . $opt . "\"";
						
			switch ($details['type']) {
				case "bool":
					$val = (int)self::getOption($opt);

					$row .= "	type=\"checkbox\" 
								value=\"1\"".($val === 0 ? "" : " checked")." />";
					break;
				case "string":
				case "int":
				default:
					$row .= "	type=\"text\" 
								class=\"regular-text\" 
								value=\"" . self::getOption($opt) . "\" />";
					break;
			}
			
			$row .= "<p class=\"description\">" . __($details['desc'], 'onesite') . '</p>';

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
		$msg = sprintf(
			__( 'ONEsite SSO plugin almost ready to configure. To start using ONEsite SSO <strong>you need to set your ONEsite SDK Devkey</strong>. You can do that in the <a href="%1s">ONEsite SSO settings page</a>.', 'onesite' ),
			admin_url( 'options-general.php?page=' . self::SETTINGS_NAMESPACE ) 
		);
		
		self::displayError($msg);
	}
	
	/**
	 * Alert the user that they don't have a devkey setup.
	 *
	 * @return void
	 */
	public static function adminDevkeyWrong()
	{
		$msg = sprintf(
			__( '<strong>Invalid ONEsite SDK Devkey detected.</strong>. Please update the devkey in the <a href="%1s">ONEsite SSO settings page</a>.', 'onesite' ),
			admin_url( 'options-general.php?page=' . self::SETTINGS_NAMESPACE ) 
		);
		
		self::displayError($msg);
	}
	
	/**
	 * Alert the user with a custom message.
	 *
	 * @return void
	 */
	public static function displayError($msg)
	{
		?>
		<div class="error">
			<p><?php echo $msg ?></p>
		</div>
		<?php
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
