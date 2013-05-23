<?php


$urls[] = "http://www.zone-h.org/archive/notifier=Hmei7";

$maxPage = 50;
foreach($urls as $ui=>$url){
	$notifier = end(explode("=", $url));
	for($page=0; $page<=$maxPage; $page++){
		$data = get_url_contents($url."/page=".$page);
		if(strstr($data, "cryptogram")){
			die(" [!] CAPTCHA \n\n");
		}
		$data = preg_replace("/\s+/", " ", $data);
		$sad = explode('"></td> <td></td> <td>', $data);
		if(count($sad)){
			foreach($sad as $i=>$p){
				if($i>0){
					$a = explode("</td>", $p);
					$urly = current($a);
					if($urly){
						$urly = str_replace("http://","",$urly);
						$urly = "http://".$urly;
						$url = parse_url($urly);
						$url = $url['host'];
						scann($url);
					}
				}
			}
		}
	}
}


function scann($host){
	$host = "http://".$host."/";
	$adminPath = "/administrator/components/";
	echo colorize($host."\n", "SUCCESS");
	//Components Vulns
	$xmlComponents = simplexml_load_string(file_get_contents("data/components_vulns.xml"));
	if(count($xmlComponents->component)){
		foreach($xmlComponents->component as $component){
			//Try to read component.xml
			$remoteXmlComponent = get_url_contents($host.$adminPath.$component['name']."/".end(explode("_", $component['name'])).".xml");
			if(!$remoteXmlComponent){
				//Try to read manifest.xml
				$remoteXmlComponent = get_url_contents($host.$adminPath."manifest.xml");
			}
			if($remoteXmlComponent){
				//Show version
				$remoteXmlComponent = simplexml_load_string($remoteXmlComponent);
				echo " ".$component['name']." ".$remoteXmlComponent->version."\n";
			}
		}
	}
}

function getJoomlaVersion($host){
	//Joomla https://www.gavick.com/magazine/how-to-check-the-version-of-joomla.html
	$siteSource = get_url_contents($host);
	$siteTemplateCss = get_url_contents($host."/templates/system/css/template.css");
	$siteSystemCss = get_url_contents($host."/templates/system/css/system.css");
	$siteMootools = get_url_contents($host."/media/system/js/mootools-more.js");
	$siteLang = get_url_contents($host."/language/en-GB/en-GB.ini");
	$joomlaVersion = "Unknown";
	//Joomla 1.0.x
	if(strstr($siteSource, '2005 - 2007 Open Source Matters')){
		$joomlaVersion = "1.0.x";
	}
	//Joomla 1.5
	if(strstr($siteSource, 'Joomla! 1.5" />') ||
	strstr($siteTemplateCss, "2005 - 2010 Open Source Matters")){
		$joomlaVersion = "1.5";
	}
	//Joomla 1.5.26
	if(strstr($siteLang, 'Id: en-GB.ini 11391 2009-01-04 13:35:50Z ian')){
		$joomlaVersion = "1.5.26";
	}
	//Joomla 1.6
	if(strstr($siteSource, 'Joomla! 1.6" />') ||
	strstr($siteSystemCss, "20196 2011-01-09 02:40:25Z")){
		$joomlaVersion = "1.6";
	}
	//Joomla 1.6.0 && Joomla 1.6.5
	if(strstr($siteLang, 'Id: en-GB.ini 20196 2011-01-09 02:40:25Z ian')){
		$joomlaVersion = "1.6.0 - 1.6.5";
	}
	//Joomla 1.7
	if(strstr($siteSource, 'Joomla! 1.7" /') ||
	strstr($siteSystemCss, "21322 2011-05-11 01:10:29Z dextercowley")){
		$joomlaVersion = "1.7";
	}
	//Joomla 1.7.1 && Joomla 1.7.3
	if(strstr($siteLang, 'Id: en-GB.ini 20990 2011-03-18 16:42:30Z infograf768')){
		$joomlaVersion = "1.7.1 - 1.7.3";
	}
	//Joomla 2.5
	if(strstr($siteSource, 'Joomla! 2.5" /') ||
	strstr($siteTemplateCss, "2005 - 2012 Open Source Matters")){
		$joomlaVersion = "2.5";
	}
	//Joomla 1.5.15, 1.7.1, 2.5.0-2.5.6
	$siteXmlLang = simplexml_load_string(get_url_contents($host."/language/en-GB/en-GB.xml"));
	if(is_object($siteXmlLang )){
		if($siteXmlLang->version){
			$joomlaVersion = $siteXmlLang->version;
		}
	}
	//Joomla 3.0 alpha 2
	if(strstr($siteMootools, 'MooTools.More={version:"1.4.0.1"') && !$joomlaVersion){
		$joomlaVersion = "3.0 alpha 2";
	}
	return $joomlaVersion;
}

function showVuln($vulnerability){
	echo "  | ".colorize("* ".$vulnerability->title."\n", "FAILURE");
	//Refers
	if($vulnerability->reference){
		foreach($vulnerability->reference as $reference){
			echo "  | ".colorize("* Reference: ".$reference."\n", "FAILURE");
		}
	}
	echo "\n";
}

function get_url_contents($url){
    $crl = curl_init();
    curl_setopt($crl, CURLOPT_URL, $url);
    curl_setopt($crl, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($crl, CURLOPT_CONNECTTIMEOUT, 1);
    $r = curl_exec($crl);
	$http_status = curl_getinfo($crl, CURLINFO_HTTP_CODE);
    curl_close($crl);
	if($http_status!="404")
    	return $r;
}

function matchVersion($version, $versionString){
	$version = html_entity_decode(trim(strtolower($version)));
	$versionString = html_entity_decode(trim(strtolower($versionString)));
	if(!$versionString || !$version || $version=="unknown" || $versionString=="unknown" || $version=="157"){
		return 1;
	}
	if(strstr($versionString, "||")){
		$versions = explode("||", $versionString);
		if(count($versions)){
			foreach($versions as $versionS){
				if(matchVersion($version, $versionS, "==")){
					return 1;
				}
			}
		}
	}
	if(strstr($versionString, "x")){
		$versionString = str_replace("x", "999999999", $versionString);
		return version_compare($version, str_replace("<=", "", $versionString), "<=");
	}
	if(!strstr($versionString, "<") && !strstr($versionString, ">")){
		return version_compare($version, $versionString, "==");
	}
	if(strstr($versionString, "<=")){
		return version_compare($version, str_replace("<=", "", $versionString), "<=");
	}
	if(strstr($versionString, "<")){
		return version_compare($version, str_replace("<", "", $versionString), "<");
	}
	if(strstr($versionString, ">=")){
		return version_compare($version, str_replace(">=", "", $versionString), ">=");
	}
	if(strstr($versionString, ">")){
		return version_compare($version, str_replace(">", "", $versionString), ">");
	}
}

function colorize($text, $status) {
	//http://softkube.com/blog/generating-command-line-colors-with-php/
	$out = "";
 	switch($status) {
  		case "SUCCESS":
   			$out = "[0;32m"; //Green background
   		break;
  		case "FAILURE":
   			$out = "[0;31m"; //Red background
   		break;
  		case "WARNING":
   			$out = "[1;33m"; //Yellow background
   		break;
  		case "NOTE":
   			$out = "[0;34m"; //Blue background
   		break;
	}
 	return chr(27).$out.$text.chr(27)."[0m";
}

?>
