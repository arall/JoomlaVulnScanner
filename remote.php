<?php

$startTime = explode(' ', microtime());

echo "\n [-] Joomla Vulnerability Scanner (Remote) [-]\n\n";
 
//Help
if($argc < 2) {
	echo " Usage: php {$argv[0]} host\n";
	echo " Example : php {$argv[0]} localhost \n\n";
	exit(1);
}

$host = "http://".$argv[1]."/";
$adminPath = "/administrator/components/";

echo colorize(" [+] Scanning ".$host."\n\n", "SUCCESS");

$joomlaVersion = getJoomlaVersion($host);
echo colorize(" [+] Joomla ".$joomlaVersion."\n\n", "WARNING");

//Core Vulns
$xmlCore = simplexml_load_string(file_get_contents("data/core_vulns.xml"));
if(count($xmlCore->joomla)){
	foreach($xmlCore->joomla as $joomla){
		//Vuln Version?
		if(matchVersion($joomlaVersion, $joomla['version'])){
			//Show vulns
			foreach($joomla->vulnerability as $vulnerability){
				showVuln($vulnerability);
			}
		}
	}
}else{
	echo colorize(" [ ] Error loading core database", "FALIURE");
}
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
			echo colorize(" [+] ".$component['name']." ".$remoteXmlComponent->version."\n\n", "WARNING");
			//Find vulns
			if(count($component->vulnerability)){
				foreach($component->vulnerability as $vulnerability){
					//Vuln Version?
					if(matchVersion($remoteXmlComponent->version, $vulnerability->version)){
						showVuln($vulnerability);
					}
				}
			}
		}
	}
}else{
	echo colorize(" [ ] Error loading components database", "FALIURE");
}

$endTime = explode(' ', microtime());
echo colorize(" [+] Scan finished in ".round((($endTime[1] + $endTime[0]) - ($startTime[1] + $startTime[0])), 4)." seconds\n\n", "SUCCESS");

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
    curl_setopt($crl, CURLOPT_CONNECTTIMEOUT, 5);
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
