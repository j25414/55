<?php

error_reporting(0);

//
// CONFIGURABLE OPTIONS
//

$subfolder = "";
$myproxy = $_SERVER['HTTP_HOST'] . $subfolder;

$switchs            = array
                    (
                        'zhuan_ma'            => 1,
                        'huan_cun'            => 1,
                        'lsw_proxy'           => 0,
                        'yi_org'              => 0,
                    );

$_config            = array
                    (
                        'truth_name'               => 'jyg-com2.appspot.com',
                        'max_file_size'            => 3145728,
                        'diyStatic'                => 'htm|html|css|js|swf|jpg|gif|png',
                        'image'                    => 'jpg|gif|png',
                    );

if ($switchs['lsw_proxy'] == 1)
{
$durls = array();
$durls[0] = "riben369-i5.appspot.com";
$durls[1] = "riben369-i6.appspot.com";
$durls[2] = "riben369-i7.appspot.com";
$tshu = rand(0,2);

$_config['truth_name'] = $durls[$tshu];
}

if ($switchs['yi_org'] == 1)
{
$yurls = array();
$yurls[0] = "p1.music.my03.com";
$yurls[1] = "p5.music.my03.com";
$yurls[2] = "p4.music.my03.com";
$yshu = rand(0,2);

$yiurl = $yurls[$yshu];
}

//
// THE INITIAL VALUES
//

$_system            = array
                    (
                        'ssl'          => extension_loaded('openssl') && version_compare(PHP_VERSION, '4.3.0', '>='),
                        'uploads'      => ini_get('file_uploads'),
                        'stripslashes' => get_magic_quotes_gpc()
                    );
$_proxify           = array('text/html' => 1, 'application/xml+xhtml' => 1, 'application/xhtml+xml' => 1, 'text/css' => 1);
$_http_host         = isset($_SERVER['HTTP_HOST']) ? $_SERVER['HTTP_HOST'] : (isset($_SERVER['SERVER_NAME']) ? $_SERVER['SERVER_NAME'] : 'localhost');
$_script_url        = 'http' . ((isset($_ENV['HTTPS']) && $_ENV['HTTPS'] == 'on') || $_SERVER['SERVER_PORT'] == 443 ? 's' : '') . '://' . $_http_host . ($_SERVER['SERVER_PORT'] != 80 && $_SERVER['SERVER_PORT'] != 443 ? ':' . $_SERVER['SERVER_PORT'] : '') . $_SERVER['PHP_SELF'];
$_url               = '';
$_url_parts         = array();
$_base              = array();
$_socket            = null;
$_request_method    = $_SERVER['REQUEST_METHOD'];
$_request_headers   = '';
$_cookie            = '';
$_post_body         = '';
$_response_headers  = array();
$_response_keys     = array();  
$_http_version      = '';
$_response_code     = 0;
$_content_type      = 'text/html';
$_content_length    = false;
$_content_disp      = '';
$_set_cookie        = array();
$_retry             = false;
$_quit              = false;
$_basic_auth_header = '';
$_basic_auth_realm  = '';
$_auth_creds        = array();
$_response_body     = '';

//
// FUNCTION DECLARATIONS
//

function encode_url($url)
{
    return rawurlencode(base64_encode(strrev($url)));
}

function show_report($data){
echo '<div style="width:80%;border:2px solid #e6e6e6;padding:8px;font-size:12px;line-height:16px">';

switch ($data['category'])
{
    case 'error':
        switch ($data['group'])
        {
            case 'url':
                echo '<b>网址错误:</b><br>';
                switch ($data['type'])
                {
                    case 'internal':
                        $message = '连接指定主机失败。<br>'
                                 . '可能由于服务器不存在、连接超时、或者服务器拒绝访问。<br>'
                                 . '请重新连接，同时检查该网址是否正确。';
                        break;
                    case 'external':
                        $message = '您访问的网址格式不正确。';
                        break;
                }
                break;
            case 'resource':
                echo '<b>资源错误:</b><br>';
                $message = '您要下载的文件太大。<br>'
                . '此链接是使用免费空间制作。因为有流量限制，本系统只允许大小为 <b>' . number_format($GLOBALS['_config']['max_file_size']/1048576, 2) . ' MB</b> 以下的文件下载。<br>'
                . '您当前要下载的文件大小为：<b>' . number_format($GLOBALS['_content_length']/1048576, 2) . ' MB</b>。<br>'
                . '要下载此文件，请使用破网软件。';
                break;
        }
        
        echo $message;
        break;
}

echo '</div>';
exit(0);
}

function add_cookie($name, $value, $expires = 0)
{
    return rawurlencode(rawurlencode($name)) . '=' . rawurlencode(rawurlencode($value)) . (empty($expires) ? '' : '; expires=' . gmdate('D, d-M-Y H:i:s \G\M\T', $expires)) . '; path=/; domain=.' . $GLOBALS['_http_host'];
}

function set_post_vars($array, $parent_key = null)
{
    $temp = array();

    foreach ($array as $key => $value)
    {
        $key = isset($parent_key) ? sprintf('%s[%s]', $parent_key, urlencode($key)) : urlencode($key);
        if (is_array($value))
        {
            $temp = array_merge($temp, set_post_vars($value, $key));
        }
        else
        {
            $temp[$key] = urlencode($value);
        }
    }
    
    return $temp;
}

function set_post_files($array, $parent_key = null)
{
    $temp = array();

    foreach ($array as $key => $value)
    {
        $key = isset($parent_key) ? sprintf('%s[%s]', $parent_key, urlencode($key)) : urlencode($key);
        if (is_array($value))
        {
            $temp = array_merge_recursive($temp, set_post_files($value, $key));
        }
        else if (preg_match('#^([^\[\]]+)\[(name|type|tmp_name)\]#', $key, $m))
        {
            $temp[str_replace($m[0], $m[1], $key)][$m[2]] = $value;
        }
    }

    return $temp;
}

function url_parse($url, & $container)
{
    $temp = @parse_url($url);

    if (!empty($temp))
    {
        $temp['port_ext'] = '';
        $temp['base']     = $temp['scheme'] . '://' . $temp['host'];

        if (isset($temp['port']))
        {
            $temp['base'] .= $temp['port_ext'] = ':' . $temp['port'];
        }
        else
        {
            $temp['port'] = $temp['scheme'] === 'https' ? 443 : 80;
        }
        
        $temp['path'] = isset($temp['path']) ? $temp['path'] : '/';
        $path         = array();
        $temp['path'] = explode('/', $temp['path']);
    
        foreach ($temp['path'] as $dir)
        {
            if ($dir === '..')
            {
                array_pop($path);
            }
            else if ($dir !== '.')
            {
                for ($dir = rawurldecode($dir), $new_dir = '', $i = 0, $count_i = strlen($dir); $i < $count_i; $new_dir .= strspn($dir{$i}, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789$-_.+!*\'(),?:@&;=') ? $dir{$i} : rawurlencode($dir{$i}), ++$i);
                $path[] = $new_dir;
            }
        }

        $temp['path']     = str_replace('/%7E', '/~', '/' . ltrim(implode('/', $path), '/'));
        $temp['file']     = substr($temp['path'], strrpos($temp['path'], '/')+1);
        $temp['dir']      = substr($temp['path'], 0, strrpos($temp['path'], '/'));
        $temp['base']    .= $temp['dir'];
        $temp['prev_dir'] = substr_count($temp['path'], '/') > 1 ? substr($temp['base'], 0, strrpos($temp['base'], '/')+1) : $temp['base'] . '/';
        $container = $temp;

        return true;
    }
    
    return false;
}

function complete_url($url, $proxify = true)
{
    $url = trim($url);
    
    if ($url === '')
    {
        return '';
    }

    if (eregi('^javascript:', $url))
    {
        return $url;
    }
    
    $hash_pos = strrpos($url, '#');
    $fragment = $hash_pos !== false ? '#' . substr($url, $hash_pos) : '';
    $sep_pos  = strpos($url, '://');
    
    if ($sep_pos === false || $sep_pos > 5)
    {
        switch ($url{0})
        {
            case '/':
                $url = substr($url, 0, 2) === '//' ? $GLOBALS['_base']['scheme'] . ':' . $url : $GLOBALS['_base']['scheme'] . '://' . $GLOBALS['_base']['host'] . $GLOBALS['_base']['port_ext'] . $url;
                break;
            case '?':
                $url = $GLOBALS['_base']['base'] . '/' . $GLOBALS['_base']['file'] . $url;
                break;
            case '#':
                $proxify = false;
                break;
            case 'm':
                if (substr($url, 0, 7) == 'mailto:')
                {
                    $proxify = false;
                    break;
                }
            default:
                $url = $GLOBALS['_base']['base'] . '/' . $url;
        }
    }

    if (eregi($GLOBALS['_config']['truth_name'],$url))
    {
       $linurl = str_ireplace($GLOBALS['_config']['truth_name'], $GLOBALS['myproxy'], $url);
    }
    elseif ($GLOBALS['switchs']['yi_org'] == 1)
    {
       $linurl = "http://" . $GLOBALS['yiurl'] . "/0/?url=" . encode_url($url);
    }
    else
    {
       $linurl = $url;
    }
    $tempurl = $proxify ? $linurl . $fragment : $url;

    return $tempurl;
}

function proxify_inline_css($css)
{
    preg_match_all('#url\s*\(\s*(([^)]*(\\\))*[^)]*)(\)|$)?#i', $css, $matches, PREG_SET_ORDER);

    for ($i = 0, $count = count($matches); $i < $count; ++$i)
    {
        $css = str_replace($matches[$i][0], 'url(' . proxify_css_url($matches[$i][1]) . ')', $css);
    }
    
    return $css;
}

function proxify_css($css)
{
    $css = proxify_inline_css($css);

    preg_match_all("#@import\s*(?:\"([^\">]*)\"?|'([^'>]*)'?)([^;]*)(;|$)#i", $css, $matches, PREG_SET_ORDER);

    for ($i = 0, $count = count($matches); $i < $count; ++$i)
    {
        $delim = '"';
        $url   = $matches[$i][2];

        if (isset($matches[$i][3]))
        {
            $delim = "'";
            $url = $matches[$i][3];
        }

        $css = str_replace($matches[$i][0], '@import ' . $delim . proxify_css_url($matches[$i][1]) . $delim . (isset($matches[$i][4]) ? $matches[$i][4] : ''), $css);
    }

    return $css;
}

function proxify_css_url($url)
{
    $url   = trim($url);
    $delim = strpos($url, '"') === 0 ? '"' : (strpos($url, "'") === 0 ? "'" : '');

    return $delim . preg_replace('#([\(\),\s\'"\\\])#', '\\$1', complete_url(trim(preg_replace('#\\\(.)#', '$1', trim($url, $delim))))) . $delim;
}

function siteUri(){
	$sitefolder=explode('.php', $_SERVER['PHP_SELF']);
	return trim(dirname($sitefolder[0]),DIRECTORY_SEPARATOR).'/';
}

function mdir2($path){
	$path2 = $path;
	while(!is_dir($path2)){
		$path2 = dirname($path2);
	}
	foreach (explode('/',str_replace($path2, '', $path)) as $value){
		$path2 .= $value.'/';
		if(!is_dir($path2))
			@mkdir($path2, 0777); 
	}
}

function save_file($filenames,$data){
	$pathinfo = pathinfo($filenames);
	if(in_array($pathinfo['basename'],array('.htaccess'))||$pathinfo['extension']=='php'){
		return false;
	}
	mdir2(dirname($filenames));
	file_put_contents($filenames, $data, LOCK_EX);
}

//
// STRIP SLASHES FROM GPC IF NECESSARY
//

if ($_system['stripslashes'])
{
    function _stripslashes($value)
    {
        return is_array($value) ? array_map('_stripslashes', $value) : (is_string($value) ? stripslashes($value) : $value);
    }
    
    $_GET    = _stripslashes($_GET);
    $_POST   = _stripslashes($_POST);
    $_COOKIE = _stripslashes($_COOKIE);
}

//
// FIGURE OUT WHAT TO DO
//

if ($switchs['huan_cun'] == 1)
{

//获取当前请求的文件后缀
$thisExt = pathinfo($_SERVER['PATH_INFO'],PATHINFO_EXTENSION);

//静态文件
if(in_array($thisExt,explode("|",$_config['diyStatic'])))
{
    $filenames = dirname('a').'/'.substr($_SERVER['REDIRECT_URL'],strlen(siteUri()));
    if(is_file($filenames))
    {
        if(in_array($thisExt,explode("|",$_config['image'])))
        {
            $ima_header = "Content-Type: image/".$thisExt;
            header($ima_header);
        }
        if($thisExt=="swf")
        {
            header("Content-Type: application/x-shockwave-flash");
        }
        if($thisExt=="js")
        {
            header("Content-Type: application/x-javascript");
        }
        if($thisExt=="css")
        {
            header("Content-Type: text/css");
        }
        echo file_get_contents($filenames);
        exit();
    }
}
}

$_url = 'http://'.$_config['truth_name'].substr($_SERVER["REQUEST_URI"],strlen($subfolder));

//
// SET URL
//

if (strpos($_url, '://') === false)
{
    $_url = 'http://' . $_url;
}

if (url_parse($_url, $_url_parts))
{
    $_base = $_url_parts;
}
else
{
    show_report(array('category' => 'error', 'group' => 'url', 'type' => 'external'));
}

//
// OPEN SOCKET TO SERVER
//

do
{
    $_retry  = false;
    $_socket = @fsockopen(($_url_parts['scheme'] === 'https' && $_system['ssl'] ? 'ssl://' : 'tcp://') . $_url_parts['host'], $_url_parts['port'], $err_no, $err_str, 30);

    if ($_socket === false)
    {
        show_report(array('category' => 'error', 'group' => 'url', 'type' => 'internal'));
    }

    //
    // SET REQUEST HEADERS
    //

    $_request_headers  = $_request_method . ' ' . $_url_parts['path'];

    if (isset($_url_parts['query']))
    {
        $_request_headers .= '?';
        $query = preg_split('#([&;])#', $_url_parts['query'], -1, PREG_SPLIT_DELIM_CAPTURE);
        for ($i = 0, $count = count($query); $i < $count; $_request_headers .= implode('=', array_map('urlencode', array_map('urldecode', explode('=', $query[$i])))) . (isset($query[++$i]) ? $query[$i] : ''), $i++);
    }

    $_request_headers .= " HTTP/1.0\r\n";
    $_request_headers .= 'Host: ' . $_url_parts['host'] . $_url_parts['port_ext'] . "\r\n";

    if (isset($_SERVER['HTTP_USER_AGENT']))
    {
        $_request_headers .= 'User-Agent: ' . $_SERVER['HTTP_USER_AGENT'] . "\r\n";
    }
    if (isset($_SERVER['HTTP_ACCEPT']))
    {
        $_request_headers .= 'Accept: ' . $_SERVER['HTTP_ACCEPT'] . "\r\n";
    }
    else
    {
        $_request_headers .= "Accept: */*;q=0.1\r\n";
    }
    if (!empty($_COOKIE))
    {
        $_cookie  = '';
        $_auth_creds    = array();
    
        foreach ($_COOKIE as $cookie_id => $cookie_content)
        {
            $cookie_id      = explode(';', rawurldecode($cookie_id));
            $cookie_content = explode(';', rawurldecode($cookie_content));
    
            if ($cookie_id[0] === 'COOKIE')
            {
                $cookie_id[3] = str_replace('_', '.', $cookie_id[3]); //stupid PHP can't have dots in var names

                if (count($cookie_id) < 4 || ($cookie_content[1] == 'secure' && $_url_parts['scheme'] != 'https'))
                {
                    continue;
                }
    
                if ((preg_match('#\Q' . $cookie_id[3] . '\E$#i', $_url_parts['host']) || strtolower($cookie_id[3]) == strtolower('.' . $_url_parts['host'])) && preg_match('#^\Q' . $cookie_id[2] . '\E#', $_url_parts['path']))
                {
                    $_cookie .= ($_cookie != '' ? '; ' : '') . (empty($cookie_id[1]) ? '' : $cookie_id[1] . '=') . $cookie_content[0];
                }
            }
            else if ($cookie_id[0] === 'AUTH' && count($cookie_id) === 3)
            {
                $cookie_id[2] = str_replace('_', '.', $cookie_id[2]);

                if ($_url_parts['host'] . ':' . $_url_parts['port'] === $cookie_id[2])
                {
                    $_auth_creds[$cookie_id[1]] = $cookie_content[0];
                }
            }
        }
        
        if ($_cookie != '')
        {
            $_request_headers .= "Cookie: $_cookie\r\n";
        }
    }
    if (isset($_url_parts['user'], $_url_parts['pass']))
    {
        $_basic_auth_header = base64_encode($_url_parts['user'] . ':' . $_url_parts['pass']);
    }
    if (!empty($_basic_auth_header))
    {
        $_set_cookie[] = add_cookie("AUTH;{$_basic_auth_realm};{$_url_parts['host']}:{$_url_parts['port']}", $_basic_auth_header);
        $_request_headers .= "Authorization: Basic {$_basic_auth_header}\r\n";
    }
    else if (!empty($_basic_auth_realm) && isset($_auth_creds[$_basic_auth_realm]))
    {
        $_request_headers  .= "Authorization: Basic {$_auth_creds[$_basic_auth_realm]}\r\n";
    }
    else if (list($_basic_auth_realm, $_basic_auth_header) = each($_auth_creds))
    {
        $_request_headers .= "Authorization: Basic {$_basic_auth_header}\r\n";
    }
    if ($_request_method == 'POST')
    {   
        if (!empty($_FILES) && $_system['uploads'])
        {
            $_data_boundary = '----' . md5(uniqid(rand(), true));
            $array = set_post_vars($_POST);
    
            foreach ($array as $key => $value)
            {
                $_post_body .= "--{$_data_boundary}\r\n";
                $_post_body .= "Content-Disposition: form-data; name=\"$key\"\r\n\r\n";
                $_post_body .= urldecode($value) . "\r\n";
            }
            
            $array = set_post_files($_FILES);
    
            foreach ($array as $key => $file_info)
            {
                $_post_body .= "--{$_data_boundary}\r\n";
                $_post_body .= "Content-Disposition: form-data; name=\"$key\"; filename=\"{$file_info['name']}\"\r\n";
                $_post_body .= 'Content-Type: ' . (empty($file_info['type']) ? 'application/octet-stream' : $file_info['type']) . "\r\n\r\n";
    
                if (is_readable($file_info['tmp_name']))
                {
                    $handle = fopen($file_info['tmp_name'], 'rb');
                    $_post_body .= fread($handle, filesize($file_info['tmp_name']));
                    fclose($handle);
                }
                
                $_post_body .= "\r\n";
            }
            
            $_post_body       .= "--{$_data_boundary}--\r\n";
            $_request_headers .= "Content-Type: multipart/form-data; boundary={$_data_boundary}\r\n";
            $_request_headers .= "Content-Length: " . strlen($_post_body) . "\r\n\r\n";
            $_request_headers .= $_post_body;
        }
        else
        {
            $array = set_post_vars($_POST);
            
            foreach ($array as $key => $value)
            {
                $_post_body .= !empty($_post_body) ? '&' : '';
                $_post_body .= $key . '=' . $value;
            }
            $_request_headers .= "Content-Type: application/x-www-form-urlencoded\r\n";
            $_request_headers .= "Content-Length: " . strlen($_post_body) . "\r\n\r\n";
            $_request_headers .= $_post_body;
            $_request_headers .= "\r\n";
        }
        
        $_post_body = '';
    }
    else
    {
        $_request_headers .= "\r\n";
    }

    fwrite($_socket, $_request_headers);
    
    //
    // PROCESS RESPONSE HEADERS
    //
    
    $_response_headers = $_response_keys = array();
    
    $line = fgets($_socket, 8192);
    
    while (strspn($line, "\r\n") !== strlen($line))
    {
        @list($name, $value) = explode(':', $line, 2);
        $name = trim($name);
        $_response_headers[strtolower($name)][] = trim($value);
        $_response_keys[strtolower($name)] = $name;
        $line = fgets($_socket, 8192);
    }
    
    sscanf(current($_response_keys), '%s %s', $_http_version, $_response_code);
    
    if (isset($_response_headers['content-type']))
    {
        list($_content_type, ) = explode(';', str_replace(' ', '', strtolower($_response_headers['content-type'][0])), 2);
    }


    if (isset($_response_headers['content-length']))
    {
        $_content_length = $_response_headers['content-length'][0];
        unset($_response_headers['content-length'], $_response_keys['content-length']);
    }
    if (isset($_response_headers['content-disposition']))
    {
        $_content_disp = $_response_headers['content-disposition'][0];
        unset($_response_headers['content-disposition'], $_response_keys['content-disposition']);
    }
    if (isset($_response_headers['set-cookie']))
    {
        foreach ($_response_headers['set-cookie'] as $cookie)
        {
            $name = $value = $expires = $path = $domain = $secure = $expires_time = '';

            preg_match('#^\s*([^=;,\s]*)\s*=?\s*([^;]*)#',  $cookie, $match) && list(, $name, $value) = $match;
            preg_match('#;\s*expires\s*=\s*([^;]*)#i',      $cookie, $match) && list(, $expires)      = $match;
            preg_match('#;\s*path\s*=\s*([^;,\s]*)#i',      $cookie, $match) && list(, $path)         = $match;
            preg_match('#;\s*domain\s*=\s*([^;,\s]*)#i',    $cookie, $match) && list(, $domain)       = $match;
            preg_match('#;\s*(secure\b)#i',                 $cookie, $match) && list(, $secure)       = $match;
    
            $expires_time = empty($expires) ? 0 : intval(@strtotime($expires));
            $expires = (!empty($expires) && time()-$expires_time < 0) ? '' : $expires;
            $path    = empty($path)   ? '/' : $path;
                
            if (empty($domain))
            {
                $domain = $_url_parts['host'];
            }
            else
            {
                $domain = '.' . strtolower(str_replace('..', '.', trim($domain, '.')));
    
                if ((!preg_match('#\Q' . $domain . '\E$#i', $_url_parts['host']) && $domain != '.' . $_url_parts['host']) || (substr_count($domain, '.') < 2 && $domain{0} == '.'))
                {
                    continue;
                }
            }
            if (count($_COOKIE) >= 15 && time()-$expires_time <= 0)
            {
                $_set_cookie[] = add_cookie(current($_COOKIE), '', 1);
            }
            
            $_set_cookie[] = add_cookie("COOKIE;$name;$path;$domain", "$value;$secure", $expires_time);
        }
    }
    if (isset($_response_headers['set-cookie']))
    {
        unset($_response_headers['set-cookie'], $_response_keys['set-cookie']);
    }
    if (!empty($_set_cookie))
    {
        $_response_keys['set-cookie'] = 'Set-Cookie';
        $_response_headers['set-cookie'] = $_set_cookie;
    }
    if (isset($_response_headers['p3p']) && preg_match('#policyref\s*=\s*[\'"]?([^\'"\s]*)[\'"]?#i', $_response_headers['p3p'][0], $matches))
    {
        $_response_headers['p3p'][0] = str_replace($matches[0], 'policyref="' . complete_url($matches[1]) . '"', $_response_headers['p3p'][0]);
    }
    if (isset($_response_headers['refresh']) && preg_match('#([0-9\s]*;\s*URL\s*=)\s*(\S*)#i', $_response_headers['refresh'][0], $matches))
    {
        $_response_headers['refresh'][0] = $matches[1] . complete_url($matches[2]);
    }
    if (isset($_response_headers['location']))
    {   
        $_response_headers['location'][0] = complete_url($_response_headers['location'][0]);
    }
    if (isset($_response_headers['uri']))
    {   
        $_response_headers['uri'][0] = complete_url($_response_headers['uri'][0]);
    }
    if (isset($_response_headers['content-location']))
    {   
        $_response_headers['content-location'][0] = complete_url($_response_headers['content-location'][0]);
    }
    if (isset($_response_headers['connection']))
    {
        unset($_response_headers['connection'], $_response_keys['connection']);
    }
    if (isset($_response_headers['keep-alive']))
    {
        unset($_response_headers['keep-alive'], $_response_keys['keep-alive']);
    }
    if ($_response_code == 401 && isset($_response_headers['www-authenticate']) && preg_match('#basic\s+(?:realm="(.*?)")?#i', $_response_headers['www-authenticate'][0], $matches))
    {
        if (isset($_auth_creds[$matches[1]]) && !$_quit)
        {
            $_basic_auth_realm  = $matches[1];
            $_basic_auth_header = '';
            $_retry = $_quit = true;
        }
        else
        {
            show_report(array('category' => 'auth', 'realm' => $matches[1]));
        }
    }
}
while ($_retry);

//
// OUTPUT RESPONSE IF NO PROXIFICATION IS NEEDED
//  

if (!isset($_proxify[$_content_type]))
{
    @set_time_limit(0);
   
    $_response_keys['content-disposition'] = 'Content-Disposition';
    $_response_headers['content-disposition'][0] = empty($_content_disp) ? ($_content_type == 'application/octet_stream' ? 'attachment' : 'inline') . '; filename="' . $_url_parts['file'] . '"' : $_content_disp;
    
    if ($_content_length !== false)
    {
        if ($_config['max_file_size'] != -1 && $_content_length > $_config['max_file_size'])
        {
            show_report(array('category' => 'error', 'group' => 'resource'));
        }
        
        $_response_keys['content-length'] = 'Content-Length';
        $_response_headers['content-length'][0] = $_content_length;
    }
    
    $_response_headers   = array_filter($_response_headers);
    $_response_keys      = array_filter($_response_keys);
    
    header(array_shift($_response_keys));
    array_shift($_response_headers);
    
    foreach ($_response_headers as $name => $array)
    {
        foreach ($array as $value)
        {
            header($_response_keys[$name] . ': ' . $value, false);
        }
    }

    //静态文件缓存
    if($switchs['huan_cun'] == 1 && in_array($thisExt,explode("|",$_config['diyStatic'])))
    {
        do
        {
            $data = @fread($_socket, 8192); // silenced to avoid the "normal" warning by a faulty SSL connection
            $_response_body .= $data;
        }   
        while (isset($data{0}));
   
        unset($data);
        fclose($_socket);

        save_file($filenames,$_response_body);

        echo $_response_body;
        exit(0);
    }else{
        do
        {
            $data = fread($_socket, 8192);
            echo $data;
        }
        while (isset($data{0}));
        
        fclose($_socket);
        exit(0);
    }
}

do
{
    $data = @fread($_socket, 8192);
    $_response_body .= $data;
}   
while (isset($data{0}));
   
unset($data);
fclose($_socket);

//
// MODIFY AND DUMP RESOURCE
//

if ($_content_type == 'text/css')
{
    $_response_body = proxify_css($_response_body);
}
else
{

    //
    // PROXIFY HTML RESOURCE
    //

  if ($subfolder != "" | $switchs['yi_org'] == 1)
  {
    $tags = array
    (
        'a'          => array('href'),
        'img'        => array('src', 'longdesc'),
        'image'      => array('src', 'longdesc'),
        'body'       => array('background'),
        'base'       => array('href'),
        'frame'      => array('src', 'longdesc'),
        'iframe'     => array('src', 'longdesc'),
        'head'       => array('profile'),
        'layer'      => array('src'),
        'input'      => array('src', 'usemap'),
        'form'       => array('action'),
        'area'       => array('href'),
        'link'       => array('href', 'src', 'urn'),
        'meta'       => array('content'),
        'param'      => array('value'),
        'applet'     => array('codebase', 'code', 'object', 'archive'),
        'object'     => array('usermap', 'codebase', 'classid', 'archive', 'data'),
        'script'     => array('src'),
        'select'     => array('src'),
        'hr'         => array('src'),
        'table'      => array('background'),
        'tr'         => array('background'),
        'th'         => array('background'),
        'td'         => array('background'),
        'bgsound'    => array('src'),
        'blockquote' => array('cite'),
        'del'        => array('cite'),
        'embed'      => array('src'),
        'fig'        => array('src', 'imagemap'),
        'ilayer'     => array('src'),
        'ins'        => array('cite'),
        'note'       => array('src'),
        'overlay'    => array('src', 'imagemap'),
        'q'          => array('cite'),
        'ul'         => array('src')
    );

    preg_match_all('#(<\s*style[^>]*>)(.*?)(<\s*/\s*style[^>]*>)#is', $_response_body, $matches, PREG_SET_ORDER);

    for ($i = 0, $count_i = count($matches); $i < $count_i; ++$i)
    {
        $_response_body = str_replace($matches[$i][0], $matches[$i][1]. proxify_css($matches[$i][2]) .$matches[$i][3], $_response_body);
    }

    preg_match_all("#<\s*([a-zA-Z0-9\?-]+)([^<>]+)>#S", $_response_body, $matches);

    for ($i = 0, $count_i = count($matches[0]); $i < $count_i; ++$i)
    {
        if (!preg_match_all("#([a-zA-Z\-\/]+)\s*(?:=\s*(?:\"([^\">]*)\"?|'([^'>]*)'?|([^'\"\s]*)))?#S", $matches[2][$i], $m, PREG_SET_ORDER))
        {
            continue;
        }
        
        $rebuild    = false;
        $extra_html = $temp = '';
        $attrs      = array();

        for ($j = 0, $count_j = count($m); $j < $count_j; $attrs[strtolower($m[$j][1])] = (isset($m[$j][4]) ? $m[$j][4] : (isset($m[$j][3]) ? $m[$j][3] : (isset($m[$j][2]) ? $m[$j][2] : false))), ++$j);
        
        if (isset($attrs['style']))
        {
            $rebuild = true;
            $attrs['style'] = proxify_inline_css($attrs['style']);
        }
        
        $tag = strtolower($matches[1][$i]);

        if (isset($tags[$tag]))
        {
            switch ($tag)
            {
                case 'a':
                    if (isset($attrs['href']))
                    {
                        $rebuild = true;
                        $attrs['href'] = complete_url($attrs['href']);
                    }
                    break;
                case 'img':
                    if (isset($attrs['src']))
                    {
                        $rebuild = true;
                        $attrs['src'] = complete_url($attrs['src']);
                    }
                    if (isset($attrs['longdesc']))
                    {
                        $rebuild = true;
                        $attrs['longdesc'] = complete_url($attrs['longdesc']);
                    }
                    break;
                case 'form':
                    if (isset($attrs['action']))
                    {
                        $rebuild = true;
                        
                        if (trim($attrs['action']) === '')
                        {
                            $attrs['action'] = $_url_parts['path'];
                        }
                        $attrs['action'] = complete_url($attrs['action']);
                    }
                    break;
                case 'base':
                    if (isset($attrs['href']))
                    {
                        $rebuild = true;  
                        url_parse($attrs['href'], $_base);
                        $attrs['href'] = complete_url($attrs['href']);
                    }
                    break;
                case 'meta':
                    if (isset($attrs['http-equiv'], $attrs['content']) && preg_match('#\s*refresh\s*#i', $attrs['http-equiv']))
                    {
                        if (preg_match('#^(\s*[0-9]*\s*;\s*url=)(.*)#i', $attrs['content'], $content))
                        {                 
                            $rebuild = true;
                            $attrs['content'] =  $content[1] . complete_url(trim($content[2], '"\''));
                        }
                    }
                    break;
                case 'head':
                    if (isset($attrs['profile']))
                    {
                        $rebuild = true;
                        $attrs['profile'] = implode(' ', array_map('complete_url', explode(' ', $attrs['profile'])));
                    }
                    break;
                case 'applet':
                    if (isset($attrs['codebase']))
                    {
                        $rebuild = true;
                        $temp = $_base;
                        url_parse(complete_url(rtrim($attrs['codebase'], '/') . '/', false), $_base);
                        unset($attrs['codebase']);
                    }
                    if (isset($attrs['code']) && strpos($attrs['code'], '/') !== false)
                    {
                        $rebuild = true;
                        $attrs['code'] = complete_url($attrs['code']);
                    }
                    if (isset($attrs['object']))
                    {
                        $rebuild = true;
                        $attrs['object'] = complete_url($attrs['object']);
                    }
                    if (isset($attrs['archive']))
                    {
                        $rebuild = true;
                        $attrs['archive'] = implode(',', array_map('complete_url', preg_split('#\s*,\s*#', $attrs['archive'])));
                    }
                    if (!empty($temp))
                    {
                        $_base = $temp;
                    }
                    break;
                case 'object':
                    if (isset($attrs['usemap']))
                    {
                        $rebuild = true;
                        $attrs['usemap'] = complete_url($attrs['usemap']);
                    }
                    if (isset($attrs['codebase']))
                    {
                        $rebuild = true;
                        $temp = $_base;
                        url_parse(complete_url(rtrim($attrs['codebase'], '/') . '/', false), $_base);
                        unset($attrs['codebase']);
                    }
                    if (isset($attrs['data']))
                    {
                        $rebuild = true;
                        $attrs['data'] = complete_url($attrs['data']);
                    }
                    if (isset($attrs['classid']) && !preg_match('#^clsid:#i', $attrs['classid']))
                    {
                        $rebuild = true;
                        $attrs['classid'] = complete_url($attrs['classid']);
                    }
                    if (isset($attrs['archive']))
                    {
                        $rebuild = true;
                        $attrs['archive'] = implode(' ', array_map('complete_url', explode(' ', $attrs['archive'])));
                    }
                    if (!empty($temp))
                    {
                        $_base = $temp;
                    }
                    break;
                case 'param':
                    if (isset($attrs['valuetype'], $attrs['value']) && strtolower($attrs['valuetype']) == 'ref' && preg_match('#^[\w.+-]+://#', $attrs['value']))
                    {
                        $rebuild = true;
                        $attrs['value'] = complete_url($attrs['value']);
                    }
                    break;
                case 'frame':
                case 'iframe':
                    if (isset($attrs['src']))
                    {
                        $rebuild = true;
                        $attrs['src'] = complete_url($attrs['src']) . '&nf=1';
                    }
                    if (isset($attrs['longdesc']))
                    {
                        $rebuild = true;
                        $attrs['longdesc'] = complete_url($attrs['longdesc']);
                    }
                    break;
                default:
                    foreach ($tags[$tag] as $attr)
                    {
                        if (isset($attrs[$attr]))
                        {
                            $rebuild = true;
                            $attrs[$attr] = complete_url($attrs[$attr]);
                        }
                    }
                    break;
            }
        }
    
        if ($rebuild)
        {
            $new_tag = "<$tag";
            foreach ($attrs as $name => $value)
            {
                $delim = strpos($value, '"') && !strpos($value, "'") ? "'" : '"';
                $new_tag .= ' ' . $name . ($value !== false ? '=' . $delim . $value . $delim : '');
            }

            $_response_body = str_replace($matches[0][$i], $new_tag . '>' . $extra_html, $_response_body);
        }
    }
  }

  $_response_body = str_ireplace($_config['truth_name'], $myproxy, $_response_body);
 #if (eregi('^www\.',$_config['truth_name']))
  
if (preg_match('/^www\./i',$_config['truth_name']))
  {
     $_response_body = str_ireplace('//'.substr($_config['truth_name'],4), '//'.$myproxy, $_response_body);
  }

    //
    // 网页防过滤处理
    //

    if ($switchs['zhuan_ma'] == 1 && $_content_type == 'text/html')
    {
        $chars = '';
        preg_match("/charset=([^\>]*)\>/i", $_response_body, $matches);
        @$chart = explode('"', $matches[1]);
        @$chars = explode("'", $chart[0]);
        @$char = $chars[0];
        if(strtolower($char) == 'gb2312')
        {
            $char = 'GBK';
        }
        if($char == '')
        {
            $char = 'GBK';
        }

        $_response_body = mb_convert_encoding($_response_body,'html-entities',$char);
        $_response_body = str_replace('dongtaiwang.com', '<font color="#800000">dong</font><font color="#800080">tai</font><font color="#008000">wang</font>.com', $_response_body);
    }
}

//静态文件缓存
if($switchs['huan_cun'] == 1 && in_array($thisExt,explode("|",$_config['diyStatic'])))
{
    save_file($filenames,$_response_body);
}

$_response_keys['content-disposition'] = 'Content-Disposition';
$_response_headers['content-disposition'][0] = empty($_content_disp) ? ($_content_type == 'application/octet_stream' ? 'attachment' : 'inline') . '; filename="' . $_url_parts['file'] . '"' : $_content_disp;
$_response_keys['content-length'] = 'Content-Length';
$_response_headers['content-length'][0] = strlen($_response_body);    
$_response_headers   = array_filter($_response_headers);
$_response_keys      = array_filter($_response_keys);

header(array_shift($_response_keys));
array_shift($_response_headers);

foreach ($_response_headers as $name => $array)
{
    foreach ($array as $value)
    {
        header($_response_keys[$name] . ': ' . $value, false);
    }
}

echo $_response_body;

?>