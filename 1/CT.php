<?php
       
/*CONFIGURATION HERE*/
#$HOST = "cccamhost.example.com";
#$PORT = 4567;
#$USR = "cccam_username";
#$PASS = "cccam_password";
       

$HOST = $_GET['Host'];
$PORT = $_GET['Port'];
$USR  = $_GET['User'];
$PASS = $_GET['Pass'];
//==========================================================================================================

function hexToStr($hex)
{
    $string = "";
    for ($i=0; $i < strlen($hex)-1; $i+=2)
    {
        $string .= chr(hexdec($hex[$i].$hex[$i+1]));
    }
    return $string;
}

//==========================================================================================================

function strToHex($string)
{
    $hex_string = "";
    for ($i=0; $i < strlen($string); $i++)
    {
        $hex_string .= strtoupper(sprintf("%02x",ord($string[$i])));
    }
    return $hex_string;
}

//==========================================================================================================

function HexToBin($hexString)
{
    $hexLenght = strlen($hexString);

    if ($hexLenght % 2 != 0 || preg_match("/[^\da-fA-F]/", $hexString)) return $hexString;
    else
    {
        unset($binString);
        $binString = "";
        for ($x = 1; $x <= $hexLenght/2; $x++)
        {
            $binString .= chr(hexdec(substr($hexString,2 * $x - 2,2)));
        }        
        return $binString;
    }
}

//==========================================================================================================

function cc_crypt_swap(&$p1, &$p2) {
  $tmp = $p1;
  $p1 = $p2;
  $p2 = $tmp;
}

//==========================================================================================================

function initialize_encryption($keybin, $len) {
  global $keytable, $state, $counter, $sum;

	$i = 0;
	$j = 0;

	$key = array();
	$keytable = array();

  for ($i=0; $i<$len; $i++) $key[$i] = strToHex(substr($keybin, $i, 1));
	for ($i=0; $i<256; $i++) $keytable[$i] = $i; 

	for ($i=0; $i<256; $i++) {
		$j += hexdec($key[$i % $len]) + $keytable[$i];
		$j &= 0xff;
		cc_crypt_swap($keytable[$i], $keytable[$j]);
	}

	$state = $key[0].$key[1].$key[2].$key[3].$key[4].$key[5].$key[6].$key[7];
	//echo "state = " . $state . "<br />\n";
	$counter = 0;
	$sum = 0;
	
	for ($i=0; $i<256; $i++) $keytable[$i] = sprintf("%02X", $keytable[$i] & 0xff);
}

//==========================================================================================================

function xorr($bufbin) {
  global $keytable, $state, $counter, $sum;

  $cccam = array("C","C","c","a","m");
  $buf = array();
  $out = "";

  for ($i=0; $i<strlen($bufbin); $i++) $buf[$i] = strToHex(substr($bufbin, $i, 1));
 
  for ($i=0; $i<8; $i++) {
    $buf[8 + $i] = sprintf("%02X", ($i * hexdec($buf[$i])) & 0xff);
    if ($i < 5) $buf[$i] = strToHex(HexToBin($buf[$i]) ^ $cccam[$i]);
  }

  for ($i=0; $i<count($buf); $i++) $out .= $buf[$i];

  return $out;
}

//==========================================================================================================

function encrypt($databin, $len) {
  global $keytable, $state, $counter, $sum;

  $out = "";

  for ($i=0; $i<$len; $i++) $data[$i] = strToHex(substr($databin, $i, 1));

  for ($i=0; $i<$len; $i++) {
  	$counter = 0xff & ($counter+1);
  	$sum += hexdec($keytable[$counter]);
  	$sum &= 0xff;
    
  	cc_crypt_swap($keytable[$counter], $keytable[$sum]);

  	$z = $data[$i];
  	$data[$i] = HexToBin($z) ^ HexToBin($keytable[ (hexdec($keytable[$counter]) + hexdec($keytable[$sum])) & 0xff ]);
  	$data[$i] ^= HexToBin($state);
  	$data[$i] =  strToHex($data[$i]);
  	$state = strToHex(HexToBin($state) ^ HexToBin($z));
  }

  for ($i=0; $i<$len; $i++) $out .= $data[$i];

  return $out;
}

//==========================================================================================================

function decrypt($databin, $len) {
  global $keytable, $state, $counter, $sum;

  $out = "";

  for ($i=0; $i<$len; $i++) $data[$i] = strToHex(substr($databin, $i, 1));

  for ($i=0; $i<$len; $i++) {
  	$counter = 0xff & ($counter+1);
  	$sum += hexdec($keytable[$counter]);
  	$sum &= 0xff;
    
  	cc_crypt_swap($keytable[$counter], $keytable[$sum]);

  	$z = $data[$i];
  	$data[$i] = HexToBin($z) ^ HexToBin($keytable[ (hexdec($keytable[$counter]) + hexdec($keytable[$sum])) & 0xff ]);
  	$data[$i] ^= HexToBin($state);
  	$data[$i] =  strToHex($data[$i]);
  	$z = $data[$i];
  	$state = strToHex(HexToBin($state) ^ HexToBin($z));
  }

  for ($i=0; $i<$len; $i++) $out .= $data[$i];

  return $out;
}

//==========================================================================================================

function check_connect_checksum($databin, $length) {  
    $valid = false;
    
    $data = array();
    
    for ($i=0; $i<strlen($databin); $i++) $data[$i] = strToHex(substr($databin, $i, 1));  
  
    if ($length == 16) {  
        $sum1 = sprintf("%02X", (hexdec($data[0]) + hexdec($data[4]) + hexdec($data[8])) & 0xff);  
        $sum2 = sprintf("%02X", (hexdec($data[1]) + hexdec($data[5]) + hexdec($data[9])) & 0xff);  
        $sum3 = sprintf("%02X", (hexdec($data[2]) + hexdec($data[6]) + hexdec($data[10])) & 0xff);  
        $sum4 = sprintf("%02X", (hexdec($data[3]) + hexdec($data[7]) + hexdec($data[11])) & 0xff);  
  
        $valid = ( ($sum1 == $data[12])  
                && ($sum2 == $data[13])  
                && ($sum3 == $data[14])  
                && ($sum4 == $data[15]) );  
    }  
  
    return $valid;  
}

//==========================================================================================================

$fp = @fsockopen($HOST, $PORT, $errno, $errstr, 10);
if (!$fp) {
  echo "$errstr ($errno)<br />\n";
} else {
  $server_packet_count = 0;

  $data = fread($fp, 256);

  //printf("Got packet %d from server with length of %d.<br />\n", $server_packet_count, strlen($data));

  if (trim($data != "")) {
    $packet_valid = check_connect_checksum($data, strlen($data));
    if (!$packet_valid) {
      echo "Checksum of connection packet is not valid!<br />\n";
    } else {
      //echo "got seed from server: " . strToHex($data) . "<br />\n";
      //echo "Checksum of connection packet is valid.<br />\n";
      $data = xorr($data);
      //echo "seed xor = $data<br />\n";
      $data = HexToBin($data);
      $enc_key = strtoupper(sha1($data));
      //echo "Using this encryption key: " . $enc_key . "<br />\n";
      $enc_key = HexToBin($enc_key);

      initialize_encryption($enc_key, strlen($enc_key));      
      $decrypt_seed = decrypt($data, strlen($data));
      //echo "decrypt = " . $decrypt_seed . "<br />\n";
      $decrypt_seed = HexToBin($decrypt_seed);
 
      initialize_encryption($decrypt_seed, strlen($decrypt_seed));
      $decrypt_hash = decrypt($enc_key, strlen($enc_key));
      //echo "decrypt hash = " . $decrypt_hash . "<br />\n";
      $decrypt_hash = HexToBin($decrypt_hash);
      $encrypt_hash = encrypt($decrypt_hash, strlen($decrypt_hash));
      //echo "encrypt hash = " . $encrypt_hash . "<br />\n";
      $encrypt_hash = HexToBin($encrypt_hash);

      if (strlen($USR) > 20 || strlen($USR) == 0) {
        echo "<h2 style='color: red'>Error: username too big or empty!</h2><br />\n";
      } else {
        $username = array();
        $user = "";
        for ($i=0; $i<20; $i++) $username[$i] = "00";
        for ($i=0; $i<strlen($USR); $i++) $username[$i] = strToHex(substr($USR, $i, 1));
        for ($i=0; $i<20; $i++) $user .= $username[$i];
        $user = HexToBin($user);
        $userenc = encrypt($user, strlen($user));
        //echo "user = $user<br />\n";
        $userenc = HexToBin($userenc);
        $password = encrypt($PASS, strlen($PASS));
        //echo "password = $password<br />\n";
        $password = HexToBin($password);
        $cccam = encrypt("CCcam" . "\x00", 6);
        //echo "cccam = $cccam<br />\n";
        $cccam = HexToBin($cccam);
         
        fwrite($fp, $encrypt_hash);
        fwrite($fp, $userenc);
        fwrite($fp, $cccam);
        $data = fread($fp, 256);
        if (trim($data) != "") {
          if (!strstr(HexToBin(decrypt($data, strlen($data))), "CCcam")) 
			  echo "<h2 style='color: green'>Success!</h2><br />\n";
			} else {
			  echo "<h2 style='color: red'>Failed!</h2><br />\n";
			}
			
        $server_packet_count++;
      }

      if ($fp) fclose($fp);
    }
  } else {
    echo "<h2 style='color: red'>Reaply null bytes!</h2><br />\n";
  }
}

?>