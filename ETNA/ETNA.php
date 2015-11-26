<?php
require_once(ROOT_DIR . 'lib/Application/Authentication/namespace.php');
//require_once('Auth.php');

/**
 * Provides ETNA authentication/synchronization for Booked Scheduler
 * @see IAuthorization
 */
class ETNA extends Authentication implements IAuthentication
{/*
	public function Validate($username, $password)
	{
		echo '<script language="javascript">';
  		echo 'alert("test")';  //not showing an alert box.
  		echo '</script>';

		$url = 'http://auth.etna-alternance.net';
		$data = array('login' => $username, 'password' => $password);

		// use key 'http' even if you send the request to https://...
		$options = array(
	    	'http' => array(
	        'header'  => "Content-type: application/x-www-form-urlencoded\r\n",
	        'method'  => 'POST',
	        'content' => http_build_query($data),
	    	),
		);
		$context  = stream_context_create($options);
		//$result = file_get_contents($url, false, $context);
		echo '<script language="javascript">';
  		echo 'alert(' . $context . ')';  //not showing an alert box.
  		echo '</script>';
	}

	public function Login($username, $loginContext)
	{}*/
}