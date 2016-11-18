<?PHP

Class WPSimpleNonce {
	const option_root ='wp-snc';

  private static function get_cookie( $set_cookie ) {
    $cookie_name = 'wp-simple-nonce';
    $cookie = isset($_COOKIE[$cookie_name]) ? $_COOKIE[$cookie_name] : null;

    // If $set_cookie is changed to false after it had once been true, delete the cookie
    if ( $set_cookie === false && $cookie ) {

      // Expire the cookie
      setcookie( $cookie_name, $cookie, time()-1 );

      // Reset $cookie variable to null so we don't return an expired $cookie
      $cookie = null;
    }

    return $cookie;
  }



  public static function init( $name, $duration=86400, $set_cookie=false ) {
    $nonce = array();
    $cookie = self::get_cookie( $set_cookie );

      // Check if there's a cookie already set
      if ( $cookie ) {
        $nonce['name'] = $cookie;
        $nonce['value'] = WPSimpleNonce::fetchNonce( $cookie );

        // If there's a cookie, but the value's already been deleted from the db, get a new nonce
        if ( $nonce['value'] === null ) {
          $nonce = WPSimpleNonce::createNonce('certificate', $duration, $set_cookie );
        }

        return $nonce;
      }

      // If there's no cookie, create a new nonce
      $nonce = WPSimpleNonce::createNonce('certificate', $duration, $set_cookie );

    return $nonce;
  }



	public static function createNonce( $name, $duration, $set_cookie ) {
		if ( is_array( $name ) ) {
			if ( isset($name['name'] ) ) {
				$name = $name['name'];
			} else {
				$name = 'nonce';
			}
		}

		$id = self::generate_id();
		$name = substr( $name, 0, 17 ).'_'.$id;
		$nonce = md5( wp_salt( 'nonce' ) . $name . microtime( true ) );

		self::storeNonce( $nonce, $name, $duration );

    if ($set_cookie === true) {
      setcookie( 'wp-simple-nonce', $name, time() + $duration );
    }

		return ['name'=>$name,'value'=>$nonce];
	}



	public static function createNonceField($name='nonce') {
		if (is_array($name)) {
			if (isset($name['name'])) {
				$name = $name['name'];
			} else {
				$name = 'nonce';
			}
		}

		$name   = filter_var($name,FILTER_SANITIZE_STRING);
		$nonce  = self::createNonce($name);
		$nonce['value'] = '<input type="hidden" name="' . $nonce['name'] . '" value="'.$nonce['value'].'" />';
		return $nonce;
	}



	public static function checkNonce( $name, $value ) {
		$name = filter_var($name,FILTER_SANITIZE_STRING);
		$nonce = self::fetchNonce($name);
		$returnValue = ($nonce===$value);

		if ( $returnValue )
			self::deleteNonce($name);

		return $returnValue;
	}



	public static function  storeNonce($nonce, $name, $duration) {
		if (empty($name)) {
			return false;
		}

		$expires = time() + $duration;

		add_option(self::option_root.'_'.$name,$nonce);
		add_option(self::option_root.'_expires_'.$name,$expires);

		return true;
	}



	public static function fetchNonce($name) {
		$returnValue = get_option(self::option_root.'_'.$name);
		$nonceExpires = get_option(self::option_root.'_expires_'.$name);

		if ($nonceExpires<time()) {
			$returnValue = null;
		}

		return $returnValue;
	}



	public static function deleteNonce($name) {
		$optionDeleted = delete_option(self::option_root.'_'.$name);
		$optionDeleted = $optionDeleted && delete_option(self::option_root.'_expires_'.$name);
		return (bool)$optionDeleted;
	}



	public static function clearNonces($force=false) {
		if ( defined('WP_SETUP_CONFIG') or defined('WP_INSTALLING')  ) {
			return;
		}

		global $wpdb;

		$sql = 'SELECT option_id,
		               option_name,
		               option_value
		          FROM ' . $wpdb->options . '
		         WHERE option_name like "'.self::option_root.'_expires_%"';
		$rows = $wpdb->get_results($sql);
		$noncesDeleted = 0;

		foreach ( $rows as $singleNonce ) {

			if ($force or ($singleNonce->option_value<time())) {
				$name = substr($singleNonce->option_name, strlen(self::option_root.'_expires_'));
				$noncesDeleted +=  (self::deleteNonce($name)?1:0);
			}
		}

		return (int)$noncesDeleted;
	}



	protected static function generate_id() {
		require_once( ABSPATH . 'wp-includes/class-phpass.php');
		$hasher = new PasswordHash( 8, false );
		return md5($hasher->get_random_bytes(100,false));
	}
}

