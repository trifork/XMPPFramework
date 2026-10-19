#import "NSBundle+XMPP.h"
#import "XMPPStream.h"

#if ! __has_feature(objc_arc)
#warning This file must be compiled with ARC. Use -fobjc-arc flag (or convert project to ARC).
#endif

@implementation NSBundle (XMPP)

+ (NSBundle *)xmppFramework
{
#if SWIFT_PACKAGE && defined(SWIFTPM_MODULE_BUNDLE)
	return SWIFTPM_MODULE_BUNDLE;
#else
	return [NSBundle bundleForClass:[XMPPStream class]];
#endif
}

@end
