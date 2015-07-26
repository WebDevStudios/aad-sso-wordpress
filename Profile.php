<?php

/**
 * Class containing all profile settings and button for linking WordPress account
 * @since  0.2.1
 */
class AADSSO_Profile {

	/**
	 * A single instance of this class.
	 * @var null|AADSSO_Profile
	 */
	protected static $single_instance = null;

	/**
	 * User id of the currently logged-in user
	 *
	 * @var integer
	 */
	public $user_to_keep = 0;

	/**
	 * The AADSSO instance
	 *
	 * @var null|AADSSO
	 */
	public $aadsso = null;

	/**
	 * The AADSSO_Settings instance
	 *
	 * @var null|AADSSO_Settings
	 */
	public $settings = null;

	/**
	 * Creates or returns an instance of this class.
	 * @since  0.2.1
	 * @return AADSSO_Profile A single instance of this class.
	 */
	public static function get_instance( $aadsso ) {
		if ( null === self::$single_instance ) {
			self::$single_instance = new self( $aadsso );
		}

		return self::$single_instance;
	}

	/**
	 * Object constructor
	 *
	 * @since 0.2.1
	 *
	 * @param null|AADSSO
	 */
	protected function __construct( $aadsso = null ) {
		// Assign properties
		$this->aadsso = is_a( $aadsso, 'AADSSO' ) ? $aadsso : AADSSO::get_instance();
		$this->settings = AADSSO_Settings::load_settings();

		// Add hooks
		add_action( 'init', array( $this, 'init' ) );
	}

	/**
	 * Init hooks
	 * @since  0.2.1
	 * @return null
	 */
	public function init() {

		add_action( 'show_user_profile', array( $this, 'aad_sso_merge_button' ) );
		add_action( 'admin_init', array( $this, 'handle_redirects' ), 9999 );

		// Jump in before and after aad-sso to merge the users (if requested)
		add_filter( 'authenticate', array( $this, 'maybe_cache_user' ), 0 );
		add_filter( 'authenticate', array( $this, 'maybe_connect_user' ), 2 );

		add_action( 'all_admin_notices', array( $this, 'maybe_success_notice' ) );
	}

	/**
	 * Outputs profile section with AAD account merge button
	 *
	 * @since  0.2.1
	 *
	 * @return null
	 */
	public function aad_sso_merge_button() {
		$user_id = get_current_user_id();

		// if aadsso altsecid, no need to link the account
		if ( get_user_meta( $user_id, $this->aadsso->user_id_meta_key, 1 ) ) {
			return;
		}

		$url = wp_nonce_url( add_query_arg( 'user_id_to_map', $user_id ), 'link-aadsso', 'link-aadsso' );

		?>
		<table class="form-table">
			<tbody>
				<tr id="aadsso-link">
					<th><label><?php _e( 'Link Azure Active Directory Account', 'aad-sso' ); ?></label></th>
					<td>
						<a class="button-secondary" href="<?php echo esc_url( $url ); ?>"><?php printf( __( 'Sign in with your %s account', 'aad-sso' ), $this->settings->org_display_name ); ?></a>
						<?php do_action( 'aad_sso_link_user_description' ); ?>
					</td>
				</tr>
			</tbody>
		</table>
		<?php
	}

	/**
	 * Handles determining if redirects are needed
	 *
	 * @since  0.2.1
	 *
	 * @return null
	 */
	public function handle_redirects() {
		global $pagenow;

		$user_id = get_current_user_id();

		if ( 'profile.php' != $pagenow ) {
			$this->maybe_redirect_to_profile( $user_id );
		} else {
			$this->maybe_redirect_to_aad( $user_id );
		}

	}

	/**
	 * Handles determing if a redirect to the profile screen is needed
	 *
	 * @since  0.2.1
	 *
	 * @param  int  $user_id User ID
	 *
	 * @return null
	 */
	public function maybe_redirect_to_profile( $user_id ) {
		if ( get_user_meta( $user_id, 'aadsso_is_linked', 1 ) ) {
			wp_redirect( admin_url( 'profile.php?aadsso_is_linked' ) );
			exit;
		}
	}

	/**
	 * Handles determing if a redirect to the AAD signin experience is needed
	 *
	 * @since  0.2.1
	 *
	 * @param  int  $user_id User ID
	 *
	 * @return null
	 */
	public function maybe_redirect_to_aad( $user_id ) {
		if (
			! isset( $_GET['user_id_to_map'], $_GET['link-aadsso'] )
			|| $_GET['user_id_to_map'] != $user_id
			|| ! wp_verify_nonce( $_GET['link-aadsso'], 'link-aadsso' )
		) {
			return;
		}

		update_user_meta( $user_id, 'is_aadsso_linking', 'true' );
		wp_redirect( $this->aadsso->getLoginUrl() );
		exit;
	}

	/**
	 * Handles storing user id to an object property if the conditions are met for merging
	 *
	 * @since  0.2.1
	 *
	 * @param  mixed  $user User object or WP_Error
	 *
	 * @return mixed        User object or WP_Error
	 */
	public function maybe_cache_user( $user ) {
		$user_id = get_current_user_id();

		if (
			$user_id
			&& $this->is_redirect_from_aad()
			&& ! get_user_meta( $user_id, $this->aadsso->user_id_meta_key, 1 )
			&& get_user_meta( $user_id, 'is_aadsso_linking', 1 )
		) {
			$this->user_to_keep = $user_id;
		}

		return $user;
	}

	/**
	 * Handles merging an AAD user with the stored user
	 *
	 * @since  0.2.1
	 *
	 * @param  mixed  $user User object or WP_Error
	 *
	 * @return mixed        User object or WP_Error
	 */
	public function maybe_connect_user( $user ) {
		if (
			$this->user_to_keep
			&& is_a( $user, 'WP_User' )
			&& ( $aad_sso_id = get_user_meta( $user->ID, $this->aadsso->user_id_meta_key, 1 ) )
		) {
			$user->aad_sso_id = $aad_sso_id;
			return $this->connect_accounts( $user );
		}

		return $user;
	}

	/**
	 * Merges a new AAD user with your existing WP user
	 *
	 * @since  0.2.1
	 *
	 * @param  WP_User  $user_to_link New WP_User object to link existing WP user
	 *
	 * @return WP_User                The stored user object after merge
	 */
	public function connect_accounts( $user_to_link ) {

		delete_user_meta( $this->user_to_keep, 'is_aadsso_linking' );
		update_user_meta( $this->user_to_keep, 'aadsso_is_linked', 'true' );
		update_user_meta( $this->user_to_keep, $this->aadsso->user_id_meta_key, $user_to_link->aad_sso_id );

		// WordPress User Administration API
		require_once( ABSPATH . 'wp-admin/includes/user.php' );

		$this->reassign_comments( $user_to_link->ID );

		do_action( 'aad_sso_link_user', $user_to_link->ID, $this->user_to_keep );

		wp_delete_user( $user_to_link->ID, $this->user_to_keep );

		return get_user_by( 'id', $this->user_to_keep );
	}

	/**
	 * Re-assigns comments from a user about to be deleted to the stored user
	 *
	 * @since  0.2.1
	 *
	 * @param  int  $user_to_delete User ID of user which will be deleted
	 *
	 * @return bool                 Whether comment reassignment was successful
	 */
	protected function reassign_comments( $user_to_delete ) {
		global $wpdb;

		$result = $wpdb->update(
			$wpdb->comments,
			array(
				'user_id' => $this->user_to_keep,
			),
			array(
				'user_id' => $user_to_delete,
			),
			array( '%d' ),
			array( '%d' )
		);

		return false === $result ? false : true;
	}

	/**
	 * Determines if a merge-success message should be displayed
	 *
	 * @since  0.2.1
	 *
	 * @return null
	 */
	public function maybe_success_notice() {

		if ( ! isset( $_GET['aadsso_is_linked'] ) ) {
			return;
		}

		$user_id = get_current_user_id();

		if ( ! get_user_meta( $user_id, 'aadsso_is_linked', 1 ) ) {
			return;
		}

		echo '<div id="message" class="updated"><p>' . __( 'Success, your profile has been linked to your Azure Active Directory account.', 'aad-sso' ) . '</p></div>';

		delete_user_meta( $user_id, 'aadsso_is_linked' );

	}

	/**
	 * Determines if current request is a redirect from AAD
	 *
	 * @since  0.2.1
	 *
	 * @return boolean Whether current request is a redirect from AAD
	 */
	protected function is_redirect_from_aad() {
		return isset( $_GET['code'], $_GET['session_state'], $_GET['id_token'] );
	}

}
