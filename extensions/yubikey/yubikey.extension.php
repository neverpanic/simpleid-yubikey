<?php

/**
 *
 * Yubikey extension for the SimpleID OpenID system.
 *
 * Extends the profile page, login page and generally the display-related stuff
 * with support for Yubikey login.
 *
 * @package extensions
 */

require_once 'Auth/Yubico.php';

/**
 * Finds the user name from a specified Yubikey OTP.
 *
 * A Yubikey OTP consists of the key ID, which has 12 characters, and the OTP,
 * which has 32. Stripping the last 32 chars gives us the key ID, which can be
 * found in the filesystem store.
 *
 * @param string $otp the Yubikey OTP of the user to load
 * @return string the user name matching the Yubikey OTP, or NULL if no user
 *                matched.
 */
function store_get_uid_from_yubikey($otp) {
	// Safety check, bail out if the OTP is short
	if (strlen($otp) < 12) {
		return NULL;
	}
	// extract the key
	$keyID = substr($otp, 0, 12);

	// do a cache lookup first
	$uid = cache_get('yubikey', $keyID);
	if ($uid !== NULL) return $uid;

	$r = NULL;

	$dir = opendir(SIMPLEID_IDENTITIES_DIR);

	while (($file = readdir($dir)) !== false) {
		$filename = SIMPLEID_IDENTITIES_DIR . '/' . $file;

		if (is_link($filename)) $filename = readlink($filename);
		if ((filetype($filename) != "file") || (!preg_match('/^(.+)\.identity$/', $file, $matches))) continue;

		$uid = $matches[1];
		$test_user = store_user_load($uid);

		if (isset($test_user['auth_method']) && $test_user['auth_method'] == 'YUBIKEY') {
			if (isset($test_user['yubikey']) && is_array($test_user['yubikey'])) {
				if (isset($test_user['yubikey']['key_id']) && !is_array($test_user['yubikey']['key_id'])) {
					$test_user['yubikey']['key_id'] = [$test_user['yubikey']['key_id']];
				}
				if (isset($test_user['yubikey']['key_id']) && in_array($keyID, $test_user['yubikey']['key_id'], true)) {
					// match found
					cache_set('yubikey', $keyID, $uid);
					$r = $uid;
					break;
				}
			}
		}
	}

	closedir($dir);

	return $r;
}


/**
 * Verifies a user who relies on a Yubico Yubikey to authenticate.
 * @param string $uid the name of the user to verify
 * @param array $credentials the credentials supplied by the browser
 */
function yubikey_user_verify_credentials($uid, $credentials) {
	// check for the yubikey OTP
	if (!isset($credentials['pass'])) {
		return false;
	}

	$uid = store_get_uid_from_yubikey($credentials['pass']);
	if ($uid === NULL) {
		log_warn('No yubikey match found');
		return false;
	}

	$test_user = user_load($uid);
	if ($test_user === NULL) {
		log_warn('An identity corresponding to this Yubikey was found, but the user ' . $uid . ' could not be ' .
			'loaded. Does your cache contain stale entries?');
		return false;
	}

	// check for required settings in the identity file
	if (!isset($test_user['yubikey']) || !is_array($test_user['yubikey'])) {
		log_warn('auth_method method for ' . $test_user['uid'] . ' is YUBIKEY, but the yubikey section is missing ' .
			'from the identity file.');
		return false;
	}

	$yubi_user = &$test_user['yubikey'];
	if (   !isset($yubi_user['client_id'])
		|| !isset($yubi_user['client_key'])
		|| !isset($yubi_user['use_https'])
		|| !isset($yubi_user['key_id'])) {
		log_warn('auth_method for ' . $test_user['uid'] . ' is YUBIKEY, but at least one of the client_id, client_key, ' .
			'use_https, or key_id settings are missing from the yubikey section of the identity file.');
		return false;
	}

	// check for the yubikey OTP
	if (!isset($credentials['pass'])) {
		log_debug('auth_method for ' . $test_user['uid'] . ' is YUBIKEY, but no yubikey OTP was sent.');
		return false;
	}

	// create the verification class
	$yubi = new Auth_Yubico($yubi_user['client_id'], $yubi_user['client_key'], $yubi_user['use_https'] ? 1 : 0);

	// add custom URLs if the identity files contains any (HTTP/HTTPS is determined by the
	// user_https parameter). The library will fall back to the official Yubico servers if this
	// isn't set.
	if (isset($yubi_user['URLs']) && is_array($yubi_user['URLs'])) {
		foreach ($yubi_user['URLs'] as $url) {
			$yubi->addURLpart($url);
		}
	}

	// authenticate against the verification server
	$auth = $yubi->verify($credentials['pass']);
	if (PEAR::isError($auth)) {
		log_debug('authentication against yubikey server for user ' . $test_user['uid'] . ' failed: ' .
			$auth->getMessage());
		return false;
	}

	// verify that the given Yubikey is actually allowed to authenticate for this user. Don't do
	// this before sending the OTP to the verification server to make sure replay attacks are not
	// possible with the OTP given for this attempt.
	$parts = $yubi->parsePasswordOTP($credentials['pass']);
	if ($parts === false) {
		log_debug('authentication for user ' . $test_user['uid'] . ' failed because the OTP doesn\'t look like one.');
		return false;
	}
	if (!is_array($yubi_user['key_id'])) {
		$yubi_user['key_id'] = [$yubi_user['key_id']];
	}
	if (!in_array($parts['prefix'], $yubi_user['key_id'],true)) {
		log_debug('Yubikey authentication for user ' . $test_user['uid'] . ' expects key prefix ' .
			implode(", ", $yubi_user['key_id']) . ', but got ' . $parts['prefix']);
		return false;
	}

	// Warning: The rest of the login process continues to use $_POST['name']
	// as the UID. Since we set it to a bogus value, restore it to the expected
	// UID here.
	$_POST['name'] = $uid;

	return true;
}

/**
 * Provides additional form items when displaying the login form
 *
 * @param string $destination the SimpleID location to which the user is directed
 * if login is successful
 * @param string $state the current SimpleID state, if required by the location
 * @see user_login_form()
 */
function yubikey_user_login_form($destination, $state) {
	global $xtpl;

	$css = (isset($xtpl->vars['css'])) ? $xtpl->vars['css'] : '';
	$js  = (isset($xtpl->vars['javascript'])) ? $xtpl->vars['javascript'] : '';

	$xtpl->assign('css', $css . '@import url(' . get_base_path() . 'extensions/yubikey/yubikey.css);');
	$xtpl->assign('javascript', $js . '<script src="' . get_base_path() . 'extensions/yubikey/yubikey.js" type="text/javascript"></script>');
}

/**
 * Returns additional blocks to be displayed in the user's profile page.
 *
 * A block is coded as an array in accordance with the specifications set
 * out in {@link page.inc}.
 *
 * This hook should return an <i>array</i> of blocks, i.e. an array of
 * arrays.
 *
 * @see page_profile()
 * @return array an array of blocks to add to the user's profile page
 * @since 0.7
 */
function yubikey_page_profile() {
	global $user;

	$xtpl2 = new XTemplate('extensions/yubikey/yubikey.xtpl');

	if (!isset($user['auth_method']) || $user['auth_method'] !== 'YUBIKEY') {
		$xtpl2->parse('user_page.configwarn');
	}

	if (isset($user['yubikey'])) {
		foreach ($user['yubikey'] as $name => $value) {
			if ($name === 'client_key') {
				continue;
			}

			$xtpl2->assign('name', htmlspecialchars($name, ENT_QUOTES, 'UTF-8'));
			if (is_array($value)) {
				$xtpl2->assign('value', htmlspecialchars(implode(', ', $value), ENT_QUOTES, 'UTF-8'));
			} else {
				$xtpl2->assign('value', htmlspecialchars($value, ENT_QUOTES, 'UTF-8'));
			}
			$xtpl2->parse('user_page.yubikey');
		}
	}

	$xtpl2->parse('user_page');

	return array(array(
		'id' => 'yubikey',
		'title' => 'Yubikey Authentication',
		'content' => $xtpl2->text('user_page')
	));
}
