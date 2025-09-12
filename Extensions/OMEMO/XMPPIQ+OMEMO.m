//
//  XMPPIQ+OMEMO.m
//  XMPPFramework
//
//  Created by Chris Ballinger on 4/21/16.
//
//  XEP-0384: OMEMO Encryption
//  https://xmpp.org/extensions/xep-0384.html
//
//  This specification defines a protocol for end-to-end encryption
//  in one-on-one chats that may have multiple clients per account.

#import "XMPPIQ+OMEMO.h"
#import "XMPPIQ+XEP_0060.h"
#import "OMEMOModule.h"

@implementation XMPPIQ (OMEMO)


/**
 https://xmpp.org/extensions/xep-0384.html#example-9
  
 <iq type='get' from='juliet@capulet.lit' to='romeo@montague.lit' id='gfetch0'>
   <pubsub xmlns='http://jabber.org/protocol/pubsub'>
     <items node='urn:xmpp:omemo:2:devices'/>
   </pubsub>
 </iq>
 
 */
+ (XMPPIQ*) omemo_iqFetchDeviceIdsForJID:(XMPPJID*)jid
                               elementId:(nullable NSString*)elementId
                            xmlNamespace:(OMEMOModuleNamespace)xmlNamespace {
    NSXMLElement *items = [NSXMLElement elementWithName:@"items"];
    [items addAttributeWithName:@"node" stringValue:[OMEMOModule xmlnsOMEMODeviceList:xmlNamespace]];
    NSXMLElement *pubsub = [NSXMLElement elementWithName:@"pubsub" xmlns:XMLNS_PUBSUB];
    [pubsub addChild:items];
    
    XMPPIQ *iq = [XMPPIQ iqWithType:@"get" to:jid.bareJID elementID:elementId];
    [iq addChild:pubsub];
    return iq;
}


/** 
 https://xmpp.org/extensions/xep-0384.html#example-2
 
 <iq from='juliet@capulet.lit' type='set' id='announce1'>
   <pubsub xmlns='http://jabber.org/protocol/pubsub'>
     <publish node='urn:xmpp:omemo:2:devices'>
       <item id='current'>
         <devices xmlns='urn:xmpp:omemo:2'>
           <device id='12345' label='Dino on Lenovo Thinkpad T495' labelsig='b64/encoded/data' />
           <device id='4223' />
           <device id='31415' label='Conversations on Pixel 3' labelsig='b64/encoded/data' />
         </devices>
       </item>
     </publish>
     <publish-options>
       <x xmlns='jabber:x:data' type='submit'>
         <field var='FORM_TYPE' type='hidden'>
           <value>http://jabber.org/protocol/pubsub#publish-options</value>
         </field>
         <field var='pubsub#access_model'>
           <value>open</value>
         </field>
       </x>
     </publish-options>
   </pubsub>
 </iq>
 
 */
+ (XMPPIQ*) omemo_iqPublishDeviceIds:(NSArray<NSNumber*>*)deviceIds elementId:(nullable NSString*)elementId xmlNamespace:(OMEMOModuleNamespace)xmlNamespace {
    
    XMPPIQ *iq = [XMPPIQ iqWithType:@"set" elementID:elementId];
    
    NSXMLElement *pubsub = [NSXMLElement elementWithName:@"pubsub" xmlns:XMLNS_PUBSUB];
    [iq addChild:pubsub];
    
    NSXMLElement *publish = [NSXMLElement elementWithName:@"publish"];
    [publish addAttributeWithName:@"node" stringValue:[OMEMOModule xmlnsOMEMODeviceList:xmlNamespace]];
    [pubsub addChild:publish];
    
    NSXMLElement *item = [NSXMLElement elementWithName:@"item"];
    [item addAttributeWithName:@"id" stringValue:@"current"];
    [publish addChild:item];
    
    NSXMLElement *devices = [NSXMLElement elementWithName:@"devices" xmlns:[OMEMOModule xmlnsOMEMO:xmlNamespace]];
    [item addChild:devices];
    
    [deviceIds enumerateObjectsUsingBlock:^(NSNumber * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        NSXMLElement *device = [NSXMLElement elementWithName:@"device"];
        [device addAttributeWithName:@"id" numberValue:obj];
        [devices addChild:device];
    }];
    
    NSXMLElement *publishOptions = [NSXMLElement elementWithName:@"publish-options"];
    [pubsub addChild:publishOptions];
    
    NSXMLElement *x = [NSXMLElement elementWithName:@"x" xmlns:@"jabber:x:data"];
    [x addAttributeWithName:@"type" stringValue:@"submit"];
    [publishOptions addChild:x];
    
    NSXMLElement *formTypeField = [NSXMLElement elementWithName:@"field"];
    [formTypeField addAttributeWithName:@"var" stringValue:@"FORM_TYPE"];
    [formTypeField addAttributeWithName:@"type" stringValue:@"hidden"];
    [formTypeField addChild:[NSXMLElement elementWithName:@"value" stringValue:XMLNS_PUBSUB_PUBLISH_OPTIONS]];
    [x addChild:formTypeField];
    
    NSXMLElement *accessModelField = [NSXMLElement elementWithName:@"field"];
    [accessModelField addAttributeWithName:@"var" stringValue:@"pubsub#access_model"];
    [accessModelField addChild:[NSXMLElement elementWithName:@"value" stringValue:@"open"]];
    [x addChild:accessModelField];
    
    return iq;
}

/** iq stanza for publishing bundle for device
 
 https://xmpp.org/extensions/xep-0384.html#example-3
 https://xmpp.org/extensions/xep-0384.html#example-4 - open access model node copied over to example-3 listing
 
 <iq from='juliet@capulet.lit' type='set' id='annouce2'>
   <pubsub xmlns='http://jabber.org/protocol/pubsub'>
     <publish node='urn:xmpp:omemo:2:bundles'>
       <item id='31415'>
         <bundle xmlns='urn:xmpp:omemo:2'>
           <spk id='0'>b64/encoded/data</spk>
           <spks>b64/encoded/data</spks>
           <ik>b64/encoded/data</ik>
           <prekeys>
             <pk id='0'>b64/encoded/data</pk>
             <pk id='1'>b64/encoded/data</pk>
             <!-- … -->
             <pk id='99'>b64/encoded/data</pk>
           </prekeys>
         </bundle>
       </item>
     </publish>
     <publish-options>
       <x xmlns='jabber:x:data' type='submit'>
         <field var='FORM_TYPE' type='hidden'>
           <value>http://jabber.org/protocol/pubsub#publish-options</value>
         </field>
         <field var='pubsub#max_items'>
           <value>max</value>
         </field>
         <field var='pubsub#access_model'>
           <value>open</value>
         </field>
       </x>
     </publish-options>
   </pubsub>
 </iq>
 
 */
+ (XMPPIQ*) omemo_iqPublishBundle:(OMEMOBundle*)bundle
                 elementId:(nullable NSString*)elementId
                     xmlNamespace:(OMEMOModuleNamespace)xmlNamespace {
    XMPPIQ *iq = [XMPPIQ iqWithType:@"set" elementID:elementId];
    
    NSXMLElement *pubsub = [NSXMLElement elementWithName:@"pubsub" xmlns:XMLNS_PUBSUB];
    [iq addChild:pubsub];
    
    NSXMLElement *publish = [NSXMLElement elementWithName:@"publish"];
    NSString *nodeName = [OMEMOModule xmlnsOMEMOBundles:xmlNamespace];
    [publish addAttributeWithName:@"node" stringValue:nodeName];
    [pubsub addChild:publish];
    
    NSXMLElement *itemElement = [NSXMLElement elementWithName:@"item"];
    NSString *deviceId = [NSString stringWithFormat:@"%u", bundle.deviceId];
    [itemElement addAttributeWithName:@"id" stringValue:deviceId];
    [publish addChild:itemElement];
    
    NSXMLElement *bundleElement = [XMPPElement elementWithName:@"bundle" xmlns:[OMEMOModule xmlnsOMEMO:xmlNamespace]];
    [itemElement addChild:bundleElement];
    
    if (bundle.signedPreKey.publicKey) {
        NSXMLElement *signedPreKeyElement = [NSXMLElement elementWithName:@"spk" stringValue:[bundle.signedPreKey.publicKey base64EncodedStringWithOptions:0]];
        [signedPreKeyElement addAttributeWithName:@"id" unsignedIntegerValue:bundle.signedPreKey.preKeyId];
        [bundleElement addChild:signedPreKeyElement];
    }
    
    if (bundle.signedPreKey.signature) {
        NSXMLElement *signedPreKeySignatureElement = [NSXMLElement elementWithName:@"spks" stringValue:[bundle.signedPreKey.signature base64EncodedStringWithOptions:0]];
        [bundleElement addChild:signedPreKeySignatureElement];
    }
    
    if (bundle.identityKey) {
        NSXMLElement *identityKeyElement = [NSXMLElement elementWithName:@"ik" stringValue:[bundle.identityKey base64EncodedStringWithOptions:0]];
        [bundleElement addChild:identityKeyElement];
    }
    
    NSXMLElement *preKeysElement = [NSXMLElement elementWithName:@"prekeys"];
    [bundleElement addChild:preKeysElement];
    
    [bundle.preKeys enumerateObjectsUsingBlock:^(OMEMOPreKey * _Nonnull preKey, NSUInteger idx, BOOL * _Nonnull stop) {
        NSXMLElement *preKeyElement = [NSXMLElement elementWithName:@"pk" stringValue:[preKey.publicKey base64EncodedStringWithOptions:0]];
        [preKeyElement addAttributeWithName:@"id" unsignedIntegerValue:preKey.preKeyId];
        [preKeysElement addChild:preKeyElement];
    }];
    
    NSXMLElement *publishOptions = [NSXMLElement elementWithName:@"publish-options"];
    [pubsub addChild:publishOptions];
    
    NSXMLElement *x = [NSXMLElement elementWithName:@"x" xmlns:@"jabber:x:data"];
    [x addAttributeWithName:@"type" stringValue:@"submit"];
    [publishOptions addChild:x];
    
    NSXMLElement *formTypeField = [NSXMLElement elementWithName:@"field"];
    [formTypeField addAttributeWithName:@"var" stringValue:@"FORM_TYPE"];
    [formTypeField addAttributeWithName:@"type" stringValue:@"hidden"];
    [formTypeField addChild:[NSXMLElement elementWithName:@"value" stringValue:XMLNS_PUBSUB_PUBLISH_OPTIONS]];
    [x addChild:formTypeField];
    
    NSXMLElement *maxItemsField = [NSXMLElement elementWithName:@"field"];
    [maxItemsField addAttributeWithName:@"var" stringValue:@"pubsub#max_items"];
    [maxItemsField addChild:[NSXMLElement elementWithName:@"value" stringValue:@"max"]];
    [x addChild:maxItemsField];
    
    NSXMLElement *accessModelField = [NSXMLElement elementWithName:@"field"];
    [accessModelField addAttributeWithName:@"var" stringValue:@"pubsub#access_model"];
    [accessModelField addChild:[NSXMLElement elementWithName:@"value" stringValue:@"open"]];
    [x addChild:accessModelField];
    
    return iq;
}

+ (XMPPIQ *) omemo_iqDeleteNode:(NSString *)node elementId:(nullable NSString *)elementId {
    XMPPIQ *iq = [XMPPIQ iqWithType:@"set" elementID:elementId];
    NSXMLElement *pubsub = [NSXMLElement elementWithName:@"pubsub" xmlns:XMLNS_PUBSUB];
    NSXMLElement *deleteElement = [NSXMLElement elementWithName:@"retract"];
    [deleteElement addAttributeWithName:@"node" stringValue:node];
    
    [pubsub addChild:deleteElement];
    [iq addChild:pubsub];
    
    return iq;
}
/**
 * iq stanza for fetching remote bundle
 
 <iq type='get'
     from='romeo@montague.lit'
     to='juliet@capulet.lit'
     id='fetch1'>
   <pubsub xmlns='http://jabber.org/protocol/pubsub'>
     <items node='urn:xmpp:omemo:2:bundles'>
       <item id='31415'/>
     <items>
   </pubsub>
 </iq>
 
 */
+ (XMPPIQ*) omemo_iqFetchBundleForDeviceId:(uint32_t)deviceId
                                       jid:(XMPPJID*)jid
                                 elementId:(nullable NSString*)elementId
                              xmlNamespace:(OMEMOModuleNamespace)xmlNamespace {
    XMPPIQ *iq = [XMPPIQ iqWithType:@"get" to:jid elementID:elementId];
    
    NSXMLElement *pubsub = [NSXMLElement elementWithName:@"pubsub" xmlns:XMLNS_PUBSUB];
    [iq addChild:pubsub];
    
    NSXMLElement *itemsElement = [NSXMLElement elementWithName:@"items"];
    [itemsElement addAttributeWithName:@"node" stringValue:[OMEMOModule xmlnsOMEMOBundles:xmlNamespace]];
    [pubsub addChild:itemsElement];
    
    NSXMLElement *itemElement = [NSXMLElement elementWithName:@"item"];
    [itemElement addAttributeWithName:@"id" stringValue:[NSString stringWithFormat:@"%u", deviceId]];
    [itemsElement addChild:itemElement];
    
    return iq;
}


- (nullable OMEMOBundle*) omemo_bundle:(OMEMOModuleNamespace)ns {
    NSXMLElement *pubsub = [self elementForName:@"pubsub" xmlns:XMLNS_PUBSUB];
    if (!pubsub) { return nil; }
    
    NSXMLElement *items = [pubsub elementForName:@"items"];
    // If !items, this is a <publish> bundle and used for testing
    if (!items) {
        items = [pubsub elementForName:@"publish"];
    }
    if (!items) { return nil; }
    
    NSString *node = [items attributeForName:@"node"].stringValue;
    if (!node) { return nil; }
    if (![node isEqualToString:[OMEMOModule xmlnsOMEMOBundles:ns]]) {
        return nil;
    }
    
    NSXMLElement *itemElement = [items elementForName:@"item"];
    if (!itemElement) { return nil; }
    NSString *deviceIdString = [itemElement attributeStringValueForName:@"id"];
    uint32_t deviceId = (uint32_t)[deviceIdString integerValue];
    
    NSXMLElement *bundleElement = [itemElement elementForName:@"bundle" xmlns:[OMEMOModule xmlnsOMEMO:ns]];
    if (!bundleElement) { return nil; }
    
    NSXMLElement *signedPreKeyElement = [bundleElement elementForName:@"spk"];
    if (!signedPreKeyElement) { return nil; }
    uint32_t signedPreKeyId = [signedPreKeyElement attributeUInt32ValueForName:@"id"];
    NSString *signedPreKeyPublicBase64 = [signedPreKeyElement stringValue];
    if (!signedPreKeyPublicBase64) { return nil; }
    NSData *signedPreKeyPublic = [[NSData alloc] initWithBase64EncodedString:signedPreKeyPublicBase64 options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (!signedPreKeyPublic) { return nil; }
    
    NSString *signedPreKeySignatureBase64 = [[bundleElement elementForName:@"spks"] stringValue];
    if (!signedPreKeySignatureBase64) { return nil; }
    NSData *signedPreKeySignature = [[NSData alloc] initWithBase64EncodedString:signedPreKeySignatureBase64 options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (!signedPreKeySignature) { return nil; }
    
    NSString *identityKeyBase64 = [[bundleElement elementForName:@"ik"] stringValue];
    if (!identityKeyBase64) { return nil; }
    NSData *identityKey = [[NSData alloc] initWithBase64EncodedString:identityKeyBase64 options:NSDataBase64DecodingIgnoreUnknownCharacters];
    if (!identityKey) { return nil; }
    
    NSXMLElement *preKeysElement = [bundleElement elementForName:@"prekeys"];
    if (!preKeysElement) { return nil; }
    
    NSArray<NSXMLElement*> *preKeyElements = [preKeysElement elementsForName:@"pk"];
    NSMutableArray<OMEMOPreKey*> *preKeys = [NSMutableArray arrayWithCapacity:preKeyElements.count];
    [preKeyElements enumerateObjectsUsingBlock:^(NSXMLElement * _Nonnull obj, NSUInteger idx, BOOL * _Nonnull stop) {
        uint32_t preKeyId = [obj attributeUInt32ValueForName:@"id"];
        NSString *b64 = [obj stringValue];
        NSData *data = nil;
        if (b64) {
            data = [[NSData alloc] initWithBase64EncodedString:b64 options:NSDataBase64DecodingIgnoreUnknownCharacters];
        }
        if (data) {
            OMEMOPreKey *preKey = [[OMEMOPreKey alloc] initWithPreKeyId:preKeyId publicKey:data];
            [preKeys addObject:preKey];
        }
    }];
    
    OMEMOSignedPreKey *signedPreKey = [[OMEMOSignedPreKey alloc] initWithPreKeyId:signedPreKeyId publicKey:signedPreKeyPublic signature:signedPreKeySignature];
    OMEMOBundle *bundle = [[OMEMOBundle alloc] initWithDeviceId:deviceId identityKey:identityKey signedPreKey:signedPreKey preKeys:preKeys];
    return bundle;
}

@end
