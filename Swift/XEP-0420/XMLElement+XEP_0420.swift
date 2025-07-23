//
//  XMLElement+XEP_0420.swift
//  XMPPFramework
//
//  Created by Piotr Wegrzynek on 16/07/2025.
//

#if canImport(XMPPFramework)
import XMPPFramework
#endif

extension XMLElement {
    public static func makeStanzaContentEncryptionEnvelope() -> XMPPElement {
        XMPPElement(name: "envelope", xmlns: "urn:xmpp:sce:1")
    }
    
    public var isStanzaContentEncryptionEnvelope: Bool {
        name == "envelope" && xmlns == "urn:xmpp:sce:1"
    }
    
    public func withStanzaContentEncryptionEnvelopeContent<T>(_ body: (_ content: XMLElement) throws -> T) rethrows -> T {
        let content: XMLElement
        if let existingContent = element(forName: "content") {
            content = existingContent
        } else {
            content = XMLElement(name: "content")
            addChild(content)
        }
        return try body(content)
    }
}
