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
