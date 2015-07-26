<?php

/*
Plugin Name: Azure Active Directory Single Sign-on for WordPress
Plugin URI: http://github.com/psignoret/aad-sso-wordpress
Description: Allows you to use your organization's Azure Active Directory user accounts to log in to WordPress. If your organization is using Office 365, your user accounts are already in Azure Active Directory. This plugin uses OAuth 2.0 to authenticate users, and the Azure Active Directory Graph to get group membership and other details.
Author: Philippe Signoret
Version: 0.2.1
Author URI: http://psignoret.com/
*/

defined( 'ABSPATH' ) or die( 'No script kiddies please!' );

define( 'AADSSO_PLUGIN_URL', plugin_dir_url( __FILE__ ) );
define( 'AADSSO_PLUGIN_DIR', plugin_dir_path( __FILE__ ) );

define( 'AADSSO_SETTINGS_PATH', AADSSO_PLUGIN_DIR . 'Settings.json' );

require_once AADSSO_PLUGIN_DIR . 'Settings.php';
require_once AADSSO_PLUGIN_DIR . 'Profile.php';
require_once AADSSO_PLUGIN_DIR . 'AuthorizationHelper.php';
require_once AADSSO_PLUGIN_DIR . 'GraphHelper.php';

// TODO: Auto-load the (the exceptions at least)
require_once AADSSO_PLUGIN_DIR . 'lib/php-jwt/Authentication/JWT.php';
require_once AADSSO_PLUGIN_DIR . '/lib/php-jwt/Exceptions/BeforeValidException.php';
require_once AADSSO_PLUGIN_DIR . '/lib/php-jwt/Exceptions/ExpiredException.php';
require_once AADSSO_PLUGIN_DIR . '/lib/php-jwt/Exceptions/SignatureInvalidException.php';

class AADSSO {

	/**
	 * @var string The URL to redirect to after signing in.
	 */
	public static $redirect_uri = '';

	/**
	 * @var string The URL to redirect to after signing out (of AAD, not WP).
	 */
	public static $logout_redirect_uri = '';

	static $instance = false;
	private $settings = null;
	public $user_id_meta_key = '_aad_sso_id';

	const ANTIFORGERY_ID_KEY = 'antiforgery-id';

	protected function __construct() {

		AADSSO_Profile::get_instance( $this );

		$this->settings = AADSSO_Settings::loadSettings();

		// Set the redirect urls
		self::$redirect_uri = wp_login_url();
		self::$logout_redirect_uri = wp_login_url();

		// If plugin is not configured, we shouldn't proceed.
		if ( ! $this->plugin_is_configured() ) {
			return;
		}

		// Add the hook that starts the SESSION
		add_action( 'init', array( $this, 'register_session' ) );

		// The authenticate filter
		add_filter( 'authenticate', array( $this, 'authenticate' ), 1, 3 );

		// Some debugging locations
		//add_action( 'admin_notices', array( $this, 'printDebug' ) );
		//add_action( 'login_footer', array( $this, 'printDebug' ) );

		// Add the <style> element to the login page
		add_action( 'login_enqueue_scripts', array( $this, 'printLoginCss' ) );

		// Add the link to the organization's sign-in page
		add_action( 'login_form', array( $this, 'printLoginLink' ) );

		// Clear session variables when logging out
		add_action( 'wp_logout', array( $this, 'clearSession' ) );

		add_action( 'login_init', array( $this, 'maybeBypassLogin' ) );

		// Redirect user back to original location
		add_filter( 'login_redirect', array( $this, 'redirect_after_login' ), 20, 3 );
	}

	/**
	 * Determine if required plugin settings are stored
	 *
	 * @return bool Whether plugin is configured
	 */
	public function plugin_is_configured() {
		return isset( $this->settings->client_id, $this->settings->client_secret ) && $this->settings->client_id && $this->settings->client_secret;
	}

	public static function getInstance() {
		if ( ! self::$instance ) {
			self::$instance = new self();
		}
		return self::$instance;
	}

	/**
	 * Decides wether or not to bypass the login form and forward straight to AAD login
	 */
	public function maybeBypassLogin() {
		$bypass = apply_filters( 'aad_auto_forward_login', false );

		/*
		 * If the user is attempting to logout AND the auto-forward to AAD
		 * login is set then we need to ensure we do not auto-forward the user and get
		 * them stuck in an infinite logout loop.
		 */
		if ( $this->wantsToLogin() && $bypass && ! isset( $_GET['code'] ) ) {
			wp_redirect( $this->getLoginUrl() );
			die();
		}
	}

	public function redirect_after_login( $redirect_to, $requested_redirect_to, $user ) {
		if ( is_a( $user, 'WP_User' ) && isset( $_SESSION['redirect_to'] ) ) {
			$redirect_to = esc_url_raw( $_SESSION['redirect_to'] );
			// Remove chances of residual redirects when logging in.
			unset( $_SESSION['redirect_to'] );
		}

		return $redirect_to;
	}

	/**
	 * Checks to determine if the user wants to login on wp-login
	 *
	 * This function mostly exists to cover the exceptions to login
	 * that may exist as other parameters to $_GET[action] as $_GET[action]
	 * does not have to exist. By default WordPress assumes login if an action
	 * is not set, however this may not be true, as in the case of logout
	 * where $_GET[loggedout] is instead set
	 *
	 * @return boolean
	 */
	private function wantsToLogin() {
		$wants_to_login = false;
		// Cover default WordPress behavior
		$action = isset($_REQUEST['action']) ? $_REQUEST['action'] : 'login';
		// And now the exceptions
		$action = isset( $_GET['loggedout'] ) ? 'loggedout' : $action;
		if ( 'login' == $action ) {
			$wants_to_login = true;
		}
		return $wants_to_login;
	}

	function register_session() {
		if ( ( function_exists( 'session_status' ) && PHP_SESSION_ACTIVE !== session_status() ) || ! session_id() ) {
		  session_start();
		}
	}

	function authenticate( $user, $username, $password ) {
		// Don't re-authenticate if already authenticated
		if ( is_a( $user, 'WP_User' ) ) {
			return $user;
		}

		if ( ! isset( $_GET['code'] ) ) {

			if ( isset( $_GET['error'] ) ) {
				// The attempt to get an authorization code failed (i.e., the reply from the STS was "No.")
				return new WP_Error( $_GET['error'], sprintf( 'ERROR: Access denied to Azure Active Directory. %s', $_GET['error_description'] ) );
			}

			return $user;
		}

		if ( ! isset( $_GET['state'] ) || $_GET['state'] != $_SESSION[ self::ANTIFORGERY_ID_KEY ] ) {
			return new WP_Error( 'antiforgery_id_mismatch', sprintf( 'ANTIFORGERY_ID_KEY mismatch. Expecting %s', $_SESSION[ self::ANTIFORGERY_ID_KEY ] ) );
		}

		// Looks like we got an authorization code, let's try to get an access token
		$token = AADSSO_AuthorizationHelper::getAccessToken( $_GET['code'], $this->settings );

		if ( ! isset( $token->access_token ) ) {

			if ( isset( $token->error ) ) {
				// Unable to get an access token (although we did get an authorization code)
				return new WP_Error( $token->error, sprintf( 'ERROR: Could not get an access token to Azure Active Directory. %s', $token->error_description ) );
			}

			// None of the above, I have no idea what happened.
			return new WP_Error( 'unknown', 'ERROR: An unknown error occured.' );
		}

		// Happy path

		try {
			$jwt = AADSSO_AuthorizationHelper::validateIdToken( $token->id_token, $this->settings, $_SESSION[ self::ANTIFORGERY_ID_KEY ] );
		} catch ( Exception $e ) {
			return new WP_Error( 'invalid_id_token' , sprintf( 'ERROR: Invalid id_token. %s', $e->getMessage() ) );
		}

		// Try to find an existing user in WP with the ObjectId of the currect AAD user
		$user = $this->get_user_by_aad_id( $jwt->oid );

		// If we have a user, log them in
		if ( ! empty( $user ) && is_a( $user, 'WP_User' ) ) {
			/*
			 * At this point, we have an authorization code, an access token and the user exists in WordPress.
			 * All that's left is to set the roles based on group membership.
			 */
			if ( $this->settings->enable_aad_group_to_wp_role ) {
				$this->updateUserRoles( $user, $jwt->oid, $jwt->tid );
			}

			return apply_filters( 'aad_sso_found_user', $user, $jwt );
		}

		/*
		 * No user found. Now decide if we are allowed to create a new
		 * user or not. Will use the WordPress setting from Settings > General
		 */
		$reg_open = get_option( 'users_can_register' );
		$override_reg = apply_filters( 'aad_override_user_registration', $this->settings->override_user_registration );

		if ( ! $reg_open && ! $override_reg ) {
			return new WP_Error( 'user_not_registered', sprintf( 'ERROR: The authenticated user %s is not a registered user in this blog.', $jwt ) );
		}

		$username = explode( '@', $jwt->upn );
		$username = apply_filters( 'aad_sso_login_username', $username[0], $jwt );

		$username = get_user_by( 'login', $username )
			? 'aadsso-'. sanitize_text_field( $jwt->oid )
			: $username;

		// Setup the minimum required user data
		$userdata = array(
			'user_login'   => wp_slash( $username ),
			'user_email'   => wp_slash( $this->determine_email( $jwt ) ),
			'user_pass'    => wp_generate_password( 20, true ),
			'first_name'   => isset( $jwt->given_name ) ? esc_html( $jwt->given_name ) : '',
			'last_name'    => isset( $jwt->family_name ) ? esc_html( $jwt->family_name ) : '',
			'role'         => $this->settings->default_wp_role ? $this->settings->default_wp_role : 'subscriber',
		);

		$userdata['display_name'] = $userdata['nickname'] = $userdata['first_name'] && $userdata['last_name']
			? $userdata['first_name'] . ' ' . $userdata['last_name']
			: $userdata['first_name'];

		// Allow user-creation override
		$user = apply_filters( 'aad_sso_new_user_override', null, $userdata, $jwt );

		// If we have a user, log them in
		if ( ! empty( $user ) && is_a( $user, 'WP_User' ) ) {

			// At this point, the user exists in WordPress.
			return apply_filters( 'aad_sso_found_user', $user, $jwt );
		}

		$new_user_id = wp_insert_user( $userdata );

		if ( is_wp_error( $new_user_id ) ) {
			return $new_user_id;
		}

		// update usermeta so we know who the user is next time
		update_user_meta( $new_user_id, $this->user_id_meta_key, $jwt->oid );

		$user = new WP_User( $new_user_id );

		if ( $this->settings->enable_aad_group_to_wp_role ) {
			$this->updateUserRoles( $user, $jwt->oid, $jwt->tid );
		}

		return apply_filters( 'aad_sso_found_user', $user, $jwt );
	}

	public function get_user_by_aad_id( $aad_id ) {
		global $wpdb;
		/*
		 * We need to do this with a normal SQL query, as get_users()
		 * seems to behave unexpectedly in a multisite environment
		 */
		$query = "SELECT user_id FROM $wpdb->usermeta WHERE meta_key = $this->user_id_meta_key AND meta_value = %s";
		$query = $wpdb->prepare( $query, sanitize_text_field( $aad_id ) );
		$user_id = $wpdb->get_var( $query );
		$user = $user_id ? get_user_by( 'id', $user_id ) : false;

		return apply_filters( 'aad_sso_id_user', $user, $aad_id );
	}

	public function determine_email( $jwt ) {
		AADSSO_GraphHelper::$settings = $this->settings;
		AADSSO_GraphHelper::$tenant_id = $jwt->tid;

		$ad_user_data = AADSSO_GraphHelper::getMe();

		if ( is_wp_error( $ad_user_data ) ) {
			return $jwt->upn;
		}

		// Override the priority of the keys which get checked
		$keys_in_order          = apply_filters( 'aad_sso_emails_from_graph_check_order', array( 'proxyAddresses', 'mail', 'otherMails', 'userPrincipalName' ) );
		$keys_with_array_values = apply_filters( 'aad_sso_emails_keys_with_array_values', array( 'proxyAddresses', 'otherMails' ) );

		foreach ( $keys_in_order as $key ) {

			if ( ! isset( $ad_user_data->{$key} ) || empty( $ad_user_data->{$key} ) ) {
				continue;
			}

			if (
				in_array( $key, $keys_with_array_values )
				&& is_array( $ad_user_data->{$key} )
			) {
				return reset( $ad_user_data->{$key} );
			}

			if ( ! is_array( $ad_user_data->{$key} ) ) {
				return $ad_user_data->{$key};
			}
		}

		return $jwt->upn;
	}

	// Users AAD group memberships to set WordPress role
	function updateUserRoles( $user, $aad_object_id, $aad_tenant_id ) {
		// Pass the settings to GraphHelper
		AADSSO_GraphHelper::$settings = $this->settings;
		AADSSO_GraphHelper::$tenant_id = $aad_tenant_id;

		// Of the AAD groups defined in the settings, get only those where the user is a member
		$group_ids = array_keys( $this->settings->aad_group_to_wp_role_map );
		$group_memberships = AADSSO_GraphHelper::userCheckMemberGroups( $aad_object_id, $group_ids );

		// Determine which WordPress role the AAD group corresponds to.
		// TODO: Check for error in the group membership response (and surface in wp-login.php)
		$role_to_set = $this->settings->default_wp_role;
		if ( ! empty( $group_memberships->value ) ) {
			foreach ( $this->settings->aad_group_to_wp_role_map as $aad_group => $wp_role ) {
				if ( in_array( $aad_group, $group_memberships->value ) ) {
					$role_to_set = $wp_role;
					break;
				}
			}
		}

		if ( null != $role_to_set ) {
			// Set the role on the WordPress user
			$user->set_role( $role_to_set );
		} else {
			$token = AADSSO_AuthorizationHelper::getAccessToken( $_GET['code'], $this->settings );
			$jwt = AADSSO_AuthorizationHelper::validateIdToken( $token->id_token, $this->settings, $_SESSION[ self::ANTIFORGERY_ID_KEY ] );
			$user = new WP_Error( 'user_not_member_of_required_group', sprintf( 'ERROR: The authenticated user %s is not a member of any group granting a role.', $jwt->upn ) );
		}
	}

	function clearSession() {
		session_destroy();
	}

	function getLoginUrl() {
		$antiforgery_id = wp_create_nonce( AADSSO::ANTIFORGERY_ID_KEY );
		$_SESSION[ self::ANTIFORGERY_ID_KEY ] = $antiforgery_id;
		$_SESSION['redirect_to'] = esc_url( isset( $_GET['redirect_to'] ) ? $_GET['redirect_to'] : remove_query_arg( 'blarg' ) );
		return AADSSO_AuthorizationHelper::getAuthorizationURL( $this->settings, $antiforgery_id );
	}

	function getLogoutUrl() {
		return $this->settings->end_session_endpoint . '?' . http_build_query( array( 'post_logout_redirect_uri' => self::logout_redirect_uri( __FUNCTION__ ) ) );
	}

	/*** View ****/

	function printDebug() {
		if ( isset( $_SESSION['aadsso_debug'] ) ) {
			echo '<pre>'. print_r( $_SESSION['aadsso_var'], true ) . '</pre>';
		}
		echo '<p>DEBUG</p><pre>' . print_r( $_SESSION, true ) . '</pre>';
		echo '<pre>' . print_r( $_GET, true ) . '</pre>';
	}

	function printLoginCss() {
		wp_enqueue_style( 'aad-sso-wordpress', AADSSO_PLUGIN_URL . '/login.css' );
	}

	public function printLoginLink() {
		echo $this->getLoginLink();
	}

	function getLoginLink() {
		$login_url = $this->getLoginUrl();
		$logout_url = $this->getLogoutUrl();
		$org_display_name = $this->settings->org_display_name;

		$html = <<<EOF
			<p class="aadsso-login-form-text">
				<a href="%s">Sign in with your %s account</a><br />
				<a class="dim" href="%s">Sign out</a>
			</p>
EOF;
		$html = sprintf( $html, $login_url, htmlentities( $org_display_name ), $logout_url );
		return apply_filters( 'aad_sso_login_link', $html, $login_url, $logout_url, $org_display_name );
	}

	public static function redirect_uri( $context = '' ) {
		return apply_filters( 'aad_sso_redirect_uri', self::$redirect_uri, $context );
	}

	public static function logout_redirect_uri( $context = '' ) {
		return apply_filters( 'aad_sso_logout_redirect_uri', self::$logout_redirect_uri, $context );
	}

} // end class

$aadsso = AADSSO::getInstance();
