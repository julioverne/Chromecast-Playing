#import <Security/Security.h>
#include "ioSock.c"

static const char * reqCONNECT ="\x00\x00\x00\x58\x08\x00\x12\x08\x73\x65\x6E\x64\x65\x72\x2D\x30\x1A\x0A\x72\x65\x63\x65\x69\x76\x65\x72\x2D\x30\x22\x28\x75\x72\x6E\x3A\x78\x2D\x63\x61\x73\x74\x3A\x63\x6F\x6D\x2E\x67\x6F\x6F\x67\x6C\x65\x2E\x63\x61\x73\x74\x2E\x74\x70\x2E\x63\x6F\x6E\x6E\x65\x63\x74\x69\x6F\x6E\x28\x00\x32\x12""{\"type\":\"CONNECT\"}";
static const char * reqLAUNCH ="\x00\x00\x00\x73\x08\x00\x12\x08\x73\x65\x6E\x64\x65\x72\x2D\x30\x1A\x0A\x72\x65\x63\x65\x69\x76\x65\x72\x2D\x30\x22\x23\x75\x72\x6E\x3A\x78\x2D\x63\x61\x73\x74\x3A\x63\x6F\x6D\x2E\x67\x6F\x6F\x67\x6C\x65\x2E\x63\x61\x73\x74\x2E\x72\x65\x63\x65\x69\x76\x65\x72\x28\x00\x32\x32""{\"type\":\"LAUNCH\",\"appId\":\"CC1AD845\",\"requestId\":0}";
//static const char * reqGET_STATUS ="\x00\x00\x00\x64\x08\x00\x12\x08\x73\x65\x6E\x64\x65\x72\x2D\x30\x1A\x0A\x72\x65\x63\x65\x69\x76\x65\x72\x2D\x30\x22\x23\x75\x72\x6E\x3A\x78\x2D\x63\x61\x73\x74\x3A\x63\x6F\x6D\x2E\x67\x6F\x6F\x67\x6C\x65\x2E\x63\x61\x73\x74\x2E\x72\x65\x63\x65\x69\x76\x65\x72\x28\x00\x32\x23""{\"type\":\"GET_STATUS\",\"requestId\":0}";

static NSString* kSessionId;


static void sendMessage(SSLContextRef context, const char* message, int messageLen, BOOL waitResponse)
{
	OSStatus result;
	if(message==reqLAUNCH) {
		kSessionId = nil;
	}	
	size_t processed = 0;
	result = SSLWrite(context, message, messageLen, &processed);
	if(result) {
		printf("Error SSLWrite\n");
		return;
	}	
	if(waitResponse) {
		size_t processedRead = 0;
		char buffer[2000];
		result = SSLRead(context, buffer, 2000, &processedRead);
		if(result) {
			printf("Error SSLRead\n");
			return;
		}
		char *b = buffer;
		if(processedRead > 0) {
			NSString* receivedData = [[[NSString alloc] initWithData:[[NSData alloc] initWithBytes:(const void *)b length:processedRead]?:[NSData data] encoding:NSASCIIStringEncoding] copy];
			NSRegularExpression *regexp_filedowncount = [NSRegularExpression regularExpressionWithPattern:@"com.google.cast.media\"\\}\\],\"sessionId\":\"(.*?)\",\"" options:NSRegularExpressionCaseInsensitive error:NULL];
			NSTextCheckingResult *match_filedowncount = [regexp_filedowncount firstMatchInString:receivedData options:0 range:NSMakeRange(0, receivedData.length)];
			if(match_filedowncount) {
				NSRange  Range_filedowncount = [match_filedowncount rangeAtIndex:1];
				if ([receivedData rangeOfString:@"CC1AD845"].location != NSNotFound) {
					kSessionId = [receivedData substringWithRange:Range_filedowncount];
				}				
			}
		}
	}
}

static int startChromecastMedia(NSString* ipCastSt, NSString* urlMedia, BOOL isVideo)
{
	if(!ipCastSt || !urlMedia) {
		return 0;
	}
	if(urlMedia.length > 82) {
		printf("Error unsupported Buffer URL\n");
		return 0;
	}
	otSocket socket;
	SSLContextRef context;
	OSStatus result;
	PeerSpec peer;
	
	result = MakeServerConnection(ipCastSt.UTF8String, 8009, &socket, &peer);
	if (result)
	{
		printf("Error creating server connection\n");
		return NO;
	}
	context = SSLCreateContext(NULL, kSSLClientSide, kSSLStreamType);
	result = SSLSetIOFuncs(context, SocketRead, SocketWrite);
	if (result)
	{
		printf("Error setting SSL context callback functions\n");
		return NO;
	}
	result = SSLSetConnection(context, socket);
	if (result)
	{
		printf("Error setting the SSL context connection\n");
		return NO;
	}
	result = SSLSetPeerDomainName(context, ipCastSt.UTF8String, ipCastSt.length);
	if (result)
	{
		printf("Error setting the server domain name\n");
		return NO;
	}
	
	SSLSetClientSideAuthenticate(context, kTryAuthenticate);	
	SSLSetSessionOption(context, kSSLSessionOptionBreakOnCertRequested, true);
	SSLSetSessionOption(context, kSSLSessionOptionBreakOnServerAuth, true);
	SSLSetSessionOption(context, kSSLSessionOptionBreakOnClientAuth, true);
	
	do {result = SSLHandshake(context);} while(result == errSSLWouldBlock);
	
	
	sendMessage(context, reqCONNECT, 92, NO);
	//sendMessage(context, reqGET_STATUS, 104, YES);
	
	sendMessage(context, reqLAUNCH, 119, NO);
	sendMessage(context, reqCONNECT, 92, YES);
	do {
		sendMessage(context, reqCONNECT, 92, YES);
		if(kSessionId == nil) {
			sendMessage(context, reqLAUNCH, 119, NO);
		}
		sleep(1);
	} while(kSessionId == nil);

	
	NSMutableData *data = [NSMutableData data];
	[data appendBytes:"\x00\x00\x00\x72\x08\x00\x12\x08\x73\x65\x6E\x64\x65\x72\x2D\x30\x1A\x24" length:18];
	[data appendBytes:kSessionId.UTF8String length:36];
	[data appendBytes:"\x22\x28\x75\x72\x6E\x3A\x78\x2D\x63\x61\x73\x74\x3A\x63\x6F\x6D\x2E\x67\x6F\x6F\x67\x6C\x65\x2E\x63\x61\x73\x74\x2E\x74\x70\x2E\x63\x6F\x6E\x6E\x65\x63\x74\x69\x6F\x6E\x28\x00\x32\x12" length:46];
	[data appendBytes:"{\"type\":\"CONNECT\"}" length:18];
	sendMessage(context, (const char*)data.bytes, data.length, NO);
	
	const char* baseURL =  (const char*)(malloc(83)); // url max length 82
	memset ((void *)baseURL,'?',82);
	memcpy((void*)baseURL, urlMedia.UTF8String, urlMedia.length);
	data = [NSMutableData data];
	[data appendBytes:"\x00\x00\x01\x38\x08\x00\x12\x08\x73\x65\x6E\x64\x65\x72\x2D\x30\x1A\x24" length:18];
	[data appendBytes:kSessionId.UTF8String length:36];
	[data appendBytes:"\x22\x20\x75\x72\x6E\x3A\x78\x2D\x63\x61\x73\x74\x3A\x63\x6F\x6D\x2E\x67\x6F\x6F\x67\x6C\x65\x2E\x63\x61\x73\x74\x2E\x6D\x65\x64\x69\x61\x28\x00\x32\xDF\x01" length:39];
	[data appendBytes:"{\"type\":\"LOAD\",\"media\":{\"contentId\":\"" length:37];
	[data appendBytes:baseURL length:82];
	[data appendBytes:"\",\"streamType\":\"BUFFERED\",\"contentType\":\"" length:41];
	[data appendBytes:isVideo?"video/xxx":"audio/xxx" length:9];
	[data appendBytes:"\"},\"autoplay\":1,\"currentTime\":0,\"requestId\":921489134}" length:54];
	sendMessage(context, (const char*)data.bytes, data.length, NO);
	
	
    SSLClose(context);	
	return 0;
}

int main()
{
	
	startChromecastMedia(@"192.168.0.100", @"http://192.168.0.103/The.Walking.Dead.S07E15.WEB-DL.x264-FUM[ettv].mp4", YES);
	
	
}