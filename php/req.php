<?php
header("Content-Type: text/html; charset=utf-8");

function &memcpy(&$dest,$src,$n)
{
	$dest=substr($src,0,$n) . substr($dest,$n);
	return $dest;
}
function sendMessage($socket, $data)
{
	fwrite($socket, $data);
	fflush($socket);
	
	$response = fread($socket, 2000);
	print_r($response."\n\n\n\n");
	return $response;
}

$chromecastIP = "192.168.0.100"; // IP Local Chromecast


$urlMedia = "http://192.168.0.103/The.Walking.Dead.S07E15.WEB-DL.x264-FUM[ettv].mp4"; // max length 82


$typeMedia = "video/xxx"; // audio/xxx or video/xxx or image/xxx


 
 

 $socket = stream_socket_client('ssl://'.$chromecastIP.':8009', $errno, $errstr, 30, STREAM_CLIENT_CONNECT, stream_context_create([]));
 
 
 
 $response = sendMessage($socket, "\x00\x00\x00\x58\x08\x00\x12\x08\x73\x65\x6E\x64\x65\x72\x2D\x30\x1A\x0A\x72\x65\x63\x65\x69\x76\x65\x72\x2D\x30\x22\x28\x75\x72\x6E\x3A\x78\x2D\x63\x61\x73\x74\x3A\x63\x6F\x6D\x2E\x67\x6F\x6F\x67\x6C\x65\x2E\x63\x61\x73\x74\x2E\x74\x70\x2E\x63\x6F\x6E\x6E\x65\x63\x74\x69\x6F\x6E\x28\x00\x32\x12".'{"type":"CONNECT"}');
 
 $response = sendMessage($socket, "\x00\x00\x00\x64\x08\x00\x12\x08\x73\x65\x6E\x64\x65\x72\x2D\x30\x1A\x0A\x72\x65\x63\x65\x69\x76\x65\x72\x2D\x30\x22\x23\x75\x72\x6E\x3A\x78\x2D\x63\x61\x73\x74\x3A\x63\x6F\x6D\x2E\x67\x6F\x6F\x67\x6C\x65\x2E\x63\x61\x73\x74\x2E\x72\x65\x63\x65\x69\x76\x65\x72\x28\x00\x32\x23".'{"type":"GET_STATUS","requestId":0}');
 
 
 
 $response = sendMessage($socket, "\x00\x00\x00\x73\x08\x00\x12\x08\x73\x65\x6E\x64\x65\x72\x2D\x30\x1A\x0A\x72\x65\x63\x65\x69\x76\x65\x72\x2D\x30\x22\x23\x75\x72\x6E\x3A\x78\x2D\x63\x61\x73\x74\x3A\x63\x6F\x6D\x2E\x67\x6F\x6F\x67\x6C\x65\x2E\x63\x61\x73\x74\x2E\x72\x65\x63\x65\x69\x76\x65\x72\x28\x00\x32\x32".'{"type":"LAUNCH","appId":"CC1AD845","requestId":0}');
 
 $response = sendMessage($socket, "\x00\x00\x00\x58\x08\x00\x12\x08\x73\x65\x6E\x64\x65\x72\x2D\x30\x1A\x0A\x72\x65\x63\x65\x69\x76\x65\x72\x2D\x30\x22\x28\x75\x72\x6E\x3A\x78\x2D\x63\x61\x73\x74\x3A\x63\x6F\x6D\x2E\x67\x6F\x6F\x67\x6C\x65\x2E\x63\x61\x73\x74\x2E\x74\x70\x2E\x63\x6F\x6E\x6E\x65\x63\x74\x69\x6F\x6E\x28\x00\x32\x12".'{"type":"CONNECT"}');
 
 $sessionID = "";
 if (preg_match("/sessionId/s", $response)) {
	 preg_match("/\"sessionId\"\:\"([^\"]*)/",$response,$r);
	 $sessionID = $r[1];
 }
 
 
 $response = sendMessage($socket, "\x00\x00\x00\x72\x08\x00\x12\x08\x73\x65\x6E\x64\x65\x72\x2D\x30\x1A\x24".$sessionID."\x22\x28\x75\x72\x6E\x3A\x78\x2D\x63\x61\x73\x74\x3A\x63\x6F\x6D\x2E\x67\x6F\x6F\x67\x6C\x65\x2E\x63\x61\x73\x74\x2E\x74\x70\x2E\x63\x6F\x6E\x6E\x65\x63\x74\x69\x6F\x6E\x28\x00\x32\x12".'{"type":"CONNECT"}');
 
 
 
 $urlMediaRw = "??????????????????????????????????????????????????????????????????????????????????"; // url max length 82 
 $urlMedia = memcpy($urlMediaRw, $urlMedia, strlen($urlMedia));
 
 $response = sendMessage($socket, "\x00\x00\x01\x38\x08\x00\x12\x08\x73\x65\x6E\x64\x65\x72\x2D\x30\x1A\x24".$sessionID."\x22\x20\x75\x72\x6E\x3A\x78\x2D\x63\x61\x73\x74\x3A\x63\x6F\x6D\x2E\x67\x6F\x6F\x67\x6C\x65\x2E\x63\x61\x73\x74\x2E\x6D\x65\x64\x69\x61\x28\x00\x32\xDF\x01".'{"type":"LOAD","media":{"contentId":"'.$urlMedia.'","streamType":"BUFFERED","contentType":"'.$typeMedia.'"},"autoplay":1,"currentTime":0,"requestId":921489134}');
 
 
 
 
 
 
 
 