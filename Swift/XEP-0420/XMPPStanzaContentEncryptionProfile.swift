//
//  XMPPStanzaContentEncryptionProfile.swift
//  XMPPFramework
//
//  Created by Piotr Wegrzynek on 12/05/2026.
//

#if canImport(XMPPFramework)
import XMPPFramework
#endif

@objc public protocol XMPPStanzaContentEncryptionProfileDelegate: NSObjectProtocol {
    @objc optional func xmppStanzaContentEncryptionProfile(_ profile: XMPPStanzaContentEncryptionProfile,
                                                           didPrepareEncryptedElement encryptedElement: XMLElement,
                                                           for message: XMPPMessage)
    @objc optional func xmppStanzaContentEncryptionProfile(_ profile: XMPPStanzaContentEncryptionProfile,
                                                           didFailToPrepareEncryptedElementFor message: XMPPMessage)
    @objc optional func xmppStanzaContentEncryptionProfile(_ profile: XMPPStanzaContentEncryptionProfile,
                                                           didDecryptEnvelopeElement envelopeElement: XMLElement,
                                                           from message: XMPPMessage)
    @objc optional func xmppStanzaContentEncryptionProfile(_ profile: XMPPStanzaContentEncryptionProfile,
                                                           didFailToHandleEncryptedElementFrom message: XMPPMessage)
}

extension GCDMulticastDelegate: XMPPStanzaContentEncryptionProfileDelegate {}

open class XMPPStanzaContentEncryptionProfile: NSObject {
    private let multicast = GCDMulticastDelegate()
    
    public func prepareEncryptedElement(withEmbeddedEnvelope envelopeElement: XMLElement, forOutgoingMessage outgoingMessage: XMPPMessage) {
        // Depending on the encryption-specific SCE-profile, some affix elements are added as child elements of the <envelope/> element.
        let finalEnvelope = addAffixElemenets(to: envelopeElement, for: outgoingMessage)
        
        // The <envelope/> element is then serialized into XML and encrypted using the SCE-specific profile of the encryption mechanism in place.
        encryptEnvelopeXML(finalEnvelope.xmlString, for: outgoingMessage) { encrypted in
            self.multicast.invoke(ofType: XMPPStanzaContentEncryptionProfileDelegate.self) { multicast in
                if let encrypted {
                    multicast.xmppStanzaContentEncryptionProfile!(self, didPrepareEncryptedElement: encrypted, for: outgoingMessage)
                } else {
                    multicast.xmppStanzaContentEncryptionProfile!(self, didFailToPrepareEncryptedElementFor: outgoingMessage)
                }
            }
        }
    }
    
    public func handleEncryptedElement(fromReceivedMessage receivedMessage: XMPPMessage) {
        decryptEnvelopeXML(from: receivedMessage) { envelopeXML in
            self.multicast.invoke(ofType: XMPPStanzaContentEncryptionProfileDelegate.self) { multicast in
                guard let envelopeXML,
                      // The recipient MUST verify that the decrypted <envelope/> element contains valid XML before processing it any further. Invalid XML must be rejected.
                      let decryptedEnvelope = try? XMLElement(xmlString: envelopeXML), decryptedEnvelope.isStanzaContentEncryptionEnvelope,
                      // Depending on the affix profiles specified by the used encryption protocol, the affix elements are verified to prevent certain attacks from taking place.
                      self.verifyAffixElements(in: decryptedEnvelope, from: receivedMessage)
                else {
                    multicast.xmppStanzaContentEncryptionProfile!(self, didFailToHandleEncryptedElementFrom: receivedMessage)
                    return
                }
                
                // The result is the <envelope/> element containing the <content/> element and the affix elements as direct child elements.
                multicast.xmppStanzaContentEncryptionProfile!(self, didDecryptEnvelopeElement: decryptedEnvelope, from: receivedMessage)
                
                // The following is not implemented as it contradicts section 11. Implementation Notes, which calls to handle encrypted elements explicitly:
                // As a last step, the original unencrypted stanza is recreated by replacing the <envelope/> element of the stanza with the elements inside of the <content/> element.
            }
        }
    }
}

// Override hooks
extension XMPPStanzaContentEncryptionProfile {
    @objc open func add(_ delegate: XMPPStanzaContentEncryptionProfileDelegate, delegateQueue: dispatch_queue_t) {
        multicast.add(delegate, delegateQueue: delegateQueue)
    }
    
    @objc open func addAffixElemenets(to envelope: XMLElement, for message: XMPPMessage) -> XMLElement {
        envelope
    }
    
    @objc open func encryptEnvelopeXML(_ envelopeXML: String, for message: XMPPMessage, completion: @escaping (XMLElement?) -> Void) {
        completion(nil)
    }
    
    @objc open func decryptEnvelopeXML(from message: XMPPMessage, completion: @escaping (String?) -> Void) {
        completion(nil)
    }
    
    @objc open func verifyAffixElements(in envelope: XMLElement, from message: XMPPMessage) -> Bool {
        false
    }
}

extension XMPPStanzaContentEncryptionProfile: XMPPStanzaContentEncryptionDelegate {
    public func xmppStanzaContentEncryption(_ encryption: XMPPStanzaContentEncryption, didReceiveEncryptedMessage encryptedMessage: XMPPMessage) {
        handleEncryptedElement(fromReceivedMessage: encryptedMessage)
    }
}
