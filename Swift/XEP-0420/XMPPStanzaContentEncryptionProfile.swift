//
//  XMPPStanzaContentEncryptionProfile.swift
//  XMPPFramework
//
//  Created by Piotr Wegrzynek on 12/05/2026.
//

import Foundation
#if canImport(XMPPFramework)
import XMPPFramework
#endif

public protocol XMPPStanzaContentEncryptionProfile {
    func addAffixElements(toEnvelopeElement envelope: XMLElement, toBeEmbeddedIn xmppElement: XMPPElement)
    func encryptEnvelope(withXMLRepresentation envelopeXML: String, toBeEmbeddedIn xmppElement: XMPPElement, completion: @escaping (XMLElement?) -> Void)
    func decryptEnvelope(embeddedIn xmppElement: XMPPElement, completion: @escaping (_ encryptedElement: XMLElement?, _ envelopeXML: String?) -> Void)
    func verifyAffixElements(fromEnvelopeElement envelope: XMLElement, embeddedIn xmppElement: XMPPElement) -> Bool
}
