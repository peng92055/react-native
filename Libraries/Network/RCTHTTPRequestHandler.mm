/**
 * Copyright (c) 2015-present, Facebook, Inc.
 *
 * This source code is licensed under the MIT license found in the
 * LICENSE file in the root directory of this source tree.
 */

#import "RCTHTTPRequestHandler.h"

#import <mutex>

#import "RCTNetworking.h"

@interface RCTHTTPRequestHandler () <NSURLSessionDataDelegate>

@end

@implementation RCTHTTPRequestHandler
{
  NSMapTable *_delegates;
  NSURLSession *_session;
  std::mutex _mutex;
}

@synthesize bridge = _bridge;

RCT_EXPORT_MODULE()

- (void)invalidate
{
  [_session invalidateAndCancel];
  _session = nil;
}

- (BOOL)isValid
{
  // if session == nil and delegates != nil, we've been invalidated
  return _session || !_delegates;
}

#pragma mark - NSURLRequestHandler

- (BOOL)canHandleRequest:(NSURLRequest *)request
{
  static NSSet<NSString *> *schemes = nil;
  static dispatch_once_t onceToken;
  dispatch_once(&onceToken, ^{
    // technically, RCTHTTPRequestHandler can handle file:// as well,
    // but it's less efficient than using RCTFileRequestHandler
    schemes = [[NSSet alloc] initWithObjects:@"http", @"https", nil];
  });
  return [schemes containsObject:request.URL.scheme.lowercaseString];
}

- (NSURLSessionDataTask *)sendRequest:(NSURLRequest *)request
                         withDelegate:(id<RCTURLRequestDelegate>)delegate
{
  // Lazy setup
  if (!_session && [self isValid]) {
    NSOperationQueue *callbackQueue = [NSOperationQueue new];
    callbackQueue.maxConcurrentOperationCount = 1;
    callbackQueue.underlyingQueue = [[_bridge networking] methodQueue];
    NSURLSessionConfiguration *configuration = [NSURLSessionConfiguration defaultSessionConfiguration];
    [configuration setHTTPShouldSetCookies:YES];
    [configuration setHTTPCookieAcceptPolicy:NSHTTPCookieAcceptPolicyAlways];
    [configuration setHTTPCookieStorage:[NSHTTPCookieStorage sharedHTTPCookieStorage]];
    _session = [NSURLSession sessionWithConfiguration:configuration
                                             delegate:self
                                        delegateQueue:callbackQueue];

    std::lock_guard<std::mutex> lock(_mutex);
    _delegates = [[NSMapTable alloc] initWithKeyOptions:NSPointerFunctionsStrongMemory
                                           valueOptions:NSPointerFunctionsStrongMemory
                                               capacity:0];
  }

  NSURLSessionDataTask *task = [_session dataTaskWithRequest:request];
  {
    std::lock_guard<std::mutex> lock(_mutex);
    [_delegates setObject:delegate forKey:task];
  }
  [task resume];
  return task;
}

- (void)cancelRequest:(NSURLSessionDataTask *)task
{
  {
    std::lock_guard<std::mutex> lock(_mutex);
    [_delegates removeObjectForKey:task];
  }
  [task cancel];
}

#pragma mark - NSURLSession delegate

/*
 // 只要访问的是HTTPS的路径就会调用
 // 该方法的作用就是处理服务器返回的证书, 需要在该方法中告诉系统是否需要安装服务器返回的证书
 // NSURLAuthenticationChallenge : 授权质问
 //+ 受保护空间
 //+ 服务器返回的证书类型
 - (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *))completionHandler
 {
 //    NSLog(@"didReceiveChallenge");
 //    NSLog(@"%@", challenge.protectionSpace.authenticationMethod);
 
 // 1.从服务器返回的受保护空间中拿到证书的类型
 // 2.判断服务器返回的证书是否是服务器信任的
 if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
 NSLog(@"是服务器信任的证书");
 // 3.根据服务器返回的受保护空间创建一个证书
 //         void (^)(NSURLSessionAuthChallengeDisposition, NSURLCredential *)
 //         代理方法的completionHandler block接收两个参数:
 //         第一个参数: 代表如何处理证书
 //         第二个参数: 代表需要处理哪个证书
 //创建证书
 NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
 // 4.安装证书   completionHandler(NSURLSessionAuthChallengeUseCredential , credential);
 }
 }
 
 - (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *credential))completionHandler
 {
 completionHandler(NSURLSessionAuthChallengeUseCredential, [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust]);
 }
 
 */


- (void)URLSession:(NSURLSession *)session didReceiveChallenge:(NSURLAuthenticationChallenge *)challenge completionHandler:(void (^)(NSURLSessionAuthChallengeDisposition disposition, NSURLCredential *     credential))completionHandler
{
  NSLog(@"didReceiveChallenge ");
  if ([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodServerTrust]) {
    NSLog(@"server ---------");
    NSString *host = challenge.protectionSpace.host;
    NSLog(@"%@", host);
    NSURLCredential *credential = [NSURLCredential credentialForTrust:challenge.protectionSpace.serverTrust];
    completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
  }
  else if([challenge.protectionSpace.authenticationMethod isEqualToString:NSURLAuthenticationMethodClientCertificate])
  {
    //客户端证书认证
    //TODO:设置客户端证书认证
    // load cert
    NSLog(@"ubmp_app_client");
    NSString *path = [[NSBundle mainBundle]pathForResource:@"ubmp_app_client" ofType:@"p12"];
    NSData *p12data = [NSData dataWithContentsOfFile:path];
    CFDataRef inP12data = (__bridge CFDataRef)p12data;
    SecIdentityRef myIdentity;
    OSStatus status = [self extractIdentity:inP12data toIdentity:&myIdentity];
    if (status != 0) {
      return;
    }
    SecCertificateRef myCertificate;
    SecIdentityCopyCertificate(myIdentity, &myCertificate);
    const void *certs[] = { myCertificate };
    CFArrayRef certsArray =CFArrayCreate(NULL, certs,1,NULL);
    NSURLCredential *credential = [NSURLCredential credentialWithIdentity:myIdentity certificates:(__bridge NSArray*)certsArray persistence:NSURLCredentialPersistencePermanent];
    completionHandler(NSURLSessionAuthChallengeUseCredential, credential);
  }
}

- (OSStatus)extractIdentity:(CFDataRef)inP12Data toIdentity:(SecIdentityRef*)identity {
  OSStatus securityError = errSecSuccess;
  CFStringRef password = CFSTR("646800");
  const void *keys[] = { kSecImportExportPassphrase };
  const void *values[] = { password };
  CFDictionaryRef options = CFDictionaryCreate(NULL, keys, values, 1, NULL, NULL);
  CFArrayRef items = CFArrayCreate(NULL, 0, 0, NULL);
  securityError = SecPKCS12Import(inP12Data, options, &items);
  if (securityError == 0)
  {
    CFDictionaryRef ident = (CFDictionaryRef)CFArrayGetValueAtIndex(items,0);
    const void *tempIdentity = NULL;
    tempIdentity = CFDictionaryGetValue(ident, kSecImportItemIdentity);
    *identity = (SecIdentityRef)tempIdentity;
  }
  else
  {
    NSLog(@"ubmp_app_client.p12 error!");
  }
  
  if (options) {
    CFRelease(options);
  }
  return securityError;
}

- (void)URLSession:(NSURLSession *)session
              task:(NSURLSessionTask *)task
   didSendBodyData:(int64_t)bytesSent
    totalBytesSent:(int64_t)totalBytesSent
totalBytesExpectedToSend:(int64_t)totalBytesExpectedToSend
{
  id<RCTURLRequestDelegate> delegate;
  {
    std::lock_guard<std::mutex> lock(_mutex);
    delegate = [_delegates objectForKey:task];
  }
  [delegate URLRequest:task didSendDataWithProgress:totalBytesSent];
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)task
didReceiveResponse:(NSURLResponse *)response
 completionHandler:(void (^)(NSURLSessionResponseDisposition))completionHandler
{
  id<RCTURLRequestDelegate> delegate;
  {
    std::lock_guard<std::mutex> lock(_mutex);
    delegate = [_delegates objectForKey:task];
  }
  [delegate URLRequest:task didReceiveResponse:response];
  completionHandler(NSURLSessionResponseAllow);
}

- (void)URLSession:(NSURLSession *)session
          dataTask:(NSURLSessionDataTask *)task
    didReceiveData:(NSData *)data
{
  id<RCTURLRequestDelegate> delegate;
  {
    std::lock_guard<std::mutex> lock(_mutex);
    delegate = [_delegates objectForKey:task];
  }
  [delegate URLRequest:task didReceiveData:data];
}

- (void)URLSession:(NSURLSession *)session task:(NSURLSessionTask *)task didCompleteWithError:(NSError *)error
{
  id<RCTURLRequestDelegate> delegate;
  {
    std::lock_guard<std::mutex> lock(_mutex);
    delegate = [_delegates objectForKey:task];
    [_delegates removeObjectForKey:task];
  }
  [delegate URLRequest:task didCompleteWithError:error];
}

@end
