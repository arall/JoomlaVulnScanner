<?php
ini_set("display_errors", 1);
error_reporting(E_ALL ^ E_NOTICE ^ E_WARNING);

$vulns['core'] = simplexml_load_string(file_get_contents("data/core_vulns.xml"));
$vulns['components'] = simplexml_load_string(file_get_contents("data/components_vulns.xml"));

echo "<pre>";
$path = "/var/www/vhosts/";
if($handle = opendir($path)){
    while(false!==($domain=readdir($handle))){
    	if($domain!="." && $domain!=".."){
        	if(is_dir($path.$domain)){
        		//Domains
		        findVulns($path, $domain);
		        //Subdomains
		        $pathS = $path.$domain."/subdomains/";
		        if($handleS = opendir($pathS)) {
				    while(false!==($subdomain=readdir($handleS))){
				    	if($subdomain!="." && $subdomain!=".."){
				    		findVulns($pathS, $subdomain);
				    	}
				    }
				    closedir($handleS);
				}
        	}
    	}
    }
    closedir($handle);
}
echo "</pre>";

function findVulns($path, $domain){
	global $vulns;
	
	$httpdocs = "/httpdocs/";
	$adminPath = "/administrator/components/";
	
	//Is Joomla?
	$configPath = $path.$domain.$httpdocs."/configuration.php";
	if(file_exists($configPath)){
		//Show Domain
		echo "[+] <a target='_blank' href='http://".$domain."/'>".$domain."</a>\n";
		//Joomla version
		$joomlaVersion = checkJoomlaVersion($path.$domain."/httpdocs/");
	    echo "[-] Joomla ".$joomlaVersion."\n";
		//Core
		if(count($vulns['core']->joomla)){
			foreach($vulns['core']->joomla as $joomla){
				//Vuln Version?
				if(matchVersion($joomlaVersion, $joomla['version'])){
					//Show vulns
					foreach($joomla->vulnerability as $vulnerability){
						echo "    [!] <a href='".$vulnerability->reference."'>".$vulnerability->title."</a>\n";
					}
				}
			}
		}
		//Components
		if(count($vulns['components']->component)){
			foreach($vulns['components']->component as $component){
				//Try to read component.xml
				$xmlComponent = read_file($path.$domain.$httpdocs.$adminPath.$component['name']."/".end(explode("_", $component['name'])).".xml");
				if(!$xmlComponent){
					//Try to read manifest.xml
					$xmlComponent = read_file($path.$domain.$httpdocs.$adminPath.$component['name']."/manifest.xml");
				}
				if($xmlComponent){
					//Show version
					$xmlComponent = simplexml_load_string($xmlComponent);
					echo "[+] ".$component['name']." ".$xmlComponent->version."\n";
					//Find vulns
					if(count($component->vulnerability)){
						foreach($component->vulnerability as $vulnerability){
							//Vuln Version?
							if(matchVersion($xmlComponent->version, $vulnerability->version)){
								//Show vuln
								echo "    [!] <a href='".$vulnerability->reference."'>".$vulnerability->title."</a>\n";
							}
						}
					}
				}
			}
		}
	    //Editors
	    $cPath = $path.$domain."/httpdocs/plugins/editors/tinymce/jscripts/tiny_mce/plugins/tinybrowser/config_tinybrowser.php";
		if(is_file($cPath)){
			$data = read_file($cPath);
			$passwordHash = between($data, "password']) != '", "'");
			if($passwordHash){
	        	echo "[-] Plugin TinyMCE is already fixed\n";
	        }else{
		        echo "[!] Plugin TinyMCE is vulnerable\n";
	        }
	    }
	    echo "\n";
	}
}

function matchVersion($version, $versionString){
	$version = html_entity_decode(trim(strtolower($version)));
	$versionString = html_entity_decode(trim(strtolower($versionString)));
	if(!$versionString || !$version || $version=="unknown" || $versionString=="unknown"){
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
	//echo "[ ] ".$version." vs ".$versionString."\n";
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

function read_file($path){
	//echo "[ ] Reading ".$path."\n"; 
	$f = fopen($path, "r");
	while($line = fgets($f, 1000)){
		$data .= $line;
	}
	return $data;
}

function checkJoomlaVersion($path){
	//Changelog
	if(file_exists($path."/CHANGELOG.php")){
		$data = read_file($path."/CHANGELOG.php");
		$v = between($data, "-------------- ", " Stable Release");
		if($v){
			return $v;
		}
	}
	//Joomla! 1.0.x OR 1.7.x (includes/version.php)
	if(file_exists($path."/includes/version.php")){
		$data = read_file($path."/includes/version.php");
		$v = between($data, "RELEASE = '", "'");
		if($v){
			return $v;
		}
		return "1.0.x";
	//Joomla! 1.5.x - 1.6.x (/libraries/joomla/version.php)
	}elseif(file_exists($path."/libraries/joomla/version.php")){
		$data = read_file($path."/libraries/joomla/version.php");
		return between($data, "RELEASE 	= '", "'");
	//Joomla! 2.5.x (/libraries/cms/version.php)
	}elseif(is_dir($path."/libraries/cms/")){
		if(file_exists($path."/libraries/cms/version/version.php")){
			$data = read_file($path."/libraries/cms/version/version.php");
			$v = between($data, "RELEASE = '", "'");
			if($v){
				return $v;
			}
		}
		return "2.5.x";
	//Joomla! 1.x (/configuration.php)
	}elseif(file_exists($path."/configuration.php")){
	    $data = read_file($path."/configuration.php");
	    if(strstr($data, "mosConfig_MetaAuthor")){
	   		return "1.x";
	    }
	    return "???";
    }
	//Unknown
	return "???";
}

function between($s,$l,$r) {
	$il = strpos($s,$l,0)+strlen($l);
	$ir = strpos($s,$r,$il);
	return substr($s,$il,($ir-$il));
 }

?>