//
//  XMPPElement+XEP_0420.swift
//  XMPPFramework
//
//  Created by Piotr Wegrzynek on 12/05/2026.
//

#if canImport(XMPPFramework)
import XMPPFramework
#endif

public extension XMPPElement {
    
    // https://xmpp.org/extensions/xep-0420.html#sending
    func encrypt(embeddingSensitiveElements sensitiveElements: [XMLElement], using encryptionProfile: XMPPStanzaContentEncryptionProfile, completion: @escaping (_ isReadyToSend: Bool) -> Void) {
        // In order to send an encrypted message without leaking extension elements, the sender prepares the message by placing the sensitive extension elements inside a <content/> element and that inside an <envelope/> element.
        let envelopeElement = XMLElement.makeEncryptionEnvelope(sensitiveElements: sensitiveElements)
        
        // Depending on the encryption-specific SCE-profile, some affix elements are added as child elements of the <envelope/> element.
        encryptionProfile.addAffixElements(toEnvelopeElement: envelopeElement, toBeEmbeddedIn: self)
        
        // The <envelope/> element is then serialized into XML and encrypted using the SCE-specific profile of the encryption mechanism in place.
        encryptionProfile.encryptEnvelope(withXMLRepresentation: envelopeElement.xmlString, toBeEmbeddedIn: self) { encryptedElement in
            guard let encryptedElement else {
                completion(false)
                return
            }
            
            // The result is appended to the message.
            self.addChild(encryptedElement)
            
            // Since the outer message element does not contain a <body/> element the sender appends an unencrypted <store/> hint as specified in Message Processing Hints (XEP-0334) [7].
            (self as? XMPPMessage)?.addStorageHint(.store)
        
            // Unencrypted <envelope/> elements are NOT ALLOWED as child elements of the stanza and MUST be dropped.
            self.removeElements(forName: "envelope")
            
            // The message can then be sent to the recipient.
            completion(true)
        }
    }
    
    // https://xmpp.org/extensions/xep-0420.html#receiving
    func decrypt(using encryptionProfile: XMPPStanzaContentEncryptionProfile, completion: @escaping (_ envelopeElement: XMLElement?, _ ignoredElements: [XMLElement]) -> Void) {
        encryptionProfile.decryptEnvelope(embeddedIn: self) { encryptedElement, envelopeXML in
            // The recipient MUST verify that the decrypted <envelope/> element contains valid XML before processing it any further. Invalid XML must be rejected.
            guard let encryptedElement, let envelopeXML,
                  let envelopeElement = try? XMLElement(xmlString: envelopeXML), envelopeElement.isStanzaContentEncryptionEnvelope else {
                completion(nil, [])
                return
            }
            
            // Depending on the affix profiles specified by the used encryption protocol, the affix elements are verified to prevent certain attacks from taking place.
            guard encryptionProfile.verifyAffixElements(fromEnvelopeElement: envelopeElement, embeddedIn: self) else {
                completion(nil, [])
                return
            }
            
            // Afterwards, the extension elements inside the <content/> element are checked against the permitted list and any disallowed elements are discarded.
            envelopeElement.element(forName: "content")?.removeAllElements(where: { $0.isServerProcessed })
            
            // The following is not implemented as it contradicts section 11. Implementation Notes, which calls to handle encrypted elements explicitly:
            // As a last step, the original unencrypted stanza is recreated by replacing the <envelope/> element of the stanza with the elements inside of the <content/> element.
            
            // Furthermore the receiving client MUST ignore any extension elements considered as sensitive which are found outside of the <envelope/> element, especially as direct unencrypted child elements of the enclosing stanza.
            let ignoredElements = self.removeAllElements(where: { $0 !== encryptedElement && $0.isSensitive })
            
            completion(envelopeElement, ignoredElements)
        }
    }
}

private extension XMLElement {
    // https://xmpp.org/extensions/xep-0420.html#example-5
    static func makeEncryptionEnvelope(sensitiveElements: [XMLElement]) -> XMLElement {
        let envelope = XMLElement(name: "envelope", xmlns: "urn:xmpp:sce:1")
        let content = XMLElement(name: "content")
        for sensitiveElement in sensitiveElements {
            guard sensitiveElement.name != nil, sensitiveElement.xmlns != nil else {
                // Elements in the <content/> element MUST be identified using an element name and namespace.
                assertionFailure("Encountered element without name or namespace in <content/> element")
                continue
            }
            content.addChild(sensitiveElement)
        }
        envelope.addChild(content)
        return envelope
    }
    
    // There are certain extension elements which are required to be available to the server in order to do message routing and processing
    // Additionally there are some elements that MUST be filtered by the server.
    // Allowing for those elements to be included in, and parsed from the encrypted payload would allow a malicious client to perform a number of attacks.
    var isServerProcessed: Bool {
        // Message Processing Hints are addressed to the server and MUST therefore be accessible in plaintext.
        if xmlns == "urn:xmpp:hints" {
            return true
        }
        
        // Sending clients MUST NOT include Stanza-ID elements inside the <envelope/> element, as this would prevent the server from filtering it.
        if xmlns == XMPPStanzaIdXmlns, [XMPPStanzaIdElementName, XMPPOriginIdElementName].contains(name) {
            return true
        }
        
        // The server MUST be able to access the <addresses/> and <address/> elements in order to do message routing, so they MUST NOT be encrypted.
        if xmlns == "http://jabber.org/protocol/address" {
            return true
        }
        
        // The server needs to be able to provide stanza error information
        if name == "error", ["jabber:client", "jabber:server"].contains(xmlns) {
            return true
        }
        
        return false
    }
    
    // Contrary to this, other elements are considered sensitive and MUST NOT be available in plaintext outside the <envelope/> element.
    var isSensitive: Bool {
        !isServerProcessed
    }
    
    @discardableResult
    func removeAllElements(where shouldBeRemoved: (XMLElement) -> Bool) -> [XMLElement] {
        guard let childrenIndices = children?.indices else { return [] }
        return childrenIndices.reversed().reduce(into: []) { partialResult, childIndex in
            guard let element = child(at: UInt(childIndex)) as? XMLElement, shouldBeRemoved(element) else { return }
            removeChild(at: UInt(childIndex))
            partialResult.append(element)
        }
    }
}
