<?php

ini_set("display_errors", 1);
error_reporting(E_ALL ^ E_NOTICE ^ E_WARNING);

echo "\n [-] Joomla Vulnerability Scanner (Remote) [-]\n\n";
 
if($argc < 2) {
	echo " Usage: php {$argv[0]} host\n";
	echo " Example : php {$argv[0]} localhost \n\n";
	exit(1);
}
 
$host = "http://".$argv[1]."/";
$adminPath = "/administrator/components/";

echo " [+] Scanning ".$host."\n";

//Joomla https://www.gavick.com/magazine/how-to-check-the-version-of-joomla.html
$siteSource = file_get_contents($host);
$siteTemplateCss = file_get_contents($host."/templates/system/css/template.css");
$siteSystemCss = file_get_contents($host."/templates/system/css/system.css");
$siteMootools = file_get_contents($host."/media/system/js/mootools-more.js");
$siteLang = file_get_contents($host."/language/en-GB/en-GB.ini");
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
$siteXmlLang = simplexml_load_string(file_get_contents($host."/language/en-GB/en-GB.xml"));
if(is_object($siteXmlLang )){
	if($siteXmlLang->version){
		$joomlaVersion = $siteXmlLang->version;
	}
}
//Joomla 3.0 alpha 2
if(strstr($siteMootools, 'MooTools.More={version:"1.4.0.1"') && !$joomlaVersion){
	$joomlaVersion = "3.0 alpha 2";
}
echo " [+] Joomla ".$joomlaVersion."\n";
//Find vulns
$xmlCore = simplexml_load_string(file_get_contents("data/core_vulns.xml"));
if(count($xmlCore->joomla)){
	foreach($xmlCore->joomla as $joomla){
		//Vuln Version?
		if(matchVersion($joomlaVersion, $joomla['version'])){
			//Show vulns
			foreach($joomla->vulnerability as $vulnerability){
				echo "     [!] ".$vulnerability->title."\n";
				if($vulnerability->reference){
					echo "        [!] Reference: ".$vulnerability->reference."\n";
				}
			}
		}
	}
}else{
	echo " [ ] Error loading core database";
}
//Components
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
			echo " [+] ".$component['name']." ".$remoteXmlComponent->version."\n";
			//Find vulns
			if(count($component->vulnerability)){
				foreach($component->vulnerability as $vulnerability){
					//Vuln Version?
					if(matchVersion($remoteXmlComponent->version, $vulnerability->version)){
						//Show vuln
						echo "     [!] ".$vulnerability->title."\n";
						if($vulnerability->reference){
							echo "        [!] Reference: ".$vulnerability->reference."\n";
						}
					}
				}
			}
		}
	}
}else{
	echo " [ ] Error loading components database";
}

function get_url_contents($url){
		//echo "[ ] ".$url."\n";
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
	//echo "[ ] ".$version." vs ".$versionString."\n";
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

?>
