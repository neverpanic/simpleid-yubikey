$(document).ready(function() {
	$('input#edit-name').val('yubikey');
	$('input#edit-pass').addClass('yubiKeyInput');
	$('input#edit-pass').siblings('label').text('Yubikey:');
	$('input#edit-pass').focus();
});
