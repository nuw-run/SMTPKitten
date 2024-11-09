import NIOCore
import Foundation
import MultipartKit
@_spi(CMS) import X509

extension Mail.Content.Block {
    var headers: [String: String] {
        switch self {
        case .plain:
            return [
                "Content-Type": "text/plain; charset=utf-8",
            ]
        case .html:
            return [
                "Content-Type": "text/html; charset=utf-8",
            ]
        case .alternative(let boundary, _, _):
            return [
                "Content-Type": "multipart/alternative; boundary=\"\(boundary)\"",
            ]
        case .image(let image):
            var disposition = image.contentDisposition.disposition.rawValue

            if let filename = image.filename {
                disposition += "; filename=\"\(filename)\""
            }

            return [
                "Content-Type": image.mime,
                "Content-Disposition": disposition,
                "Content-ID": image.contentId.id,
                "Content-Transfer-Encoding": "base64",
            ]
        case .attachment(let attachment):
            var disposition = attachment.contentDisposition.disposition.rawValue

            if let filename = attachment.filename {
                disposition += "; filename=\"\(filename)\""
            }

            return [
                "Content-Type": attachment.mime,
                "Content-Disposition": disposition,
                "Content-Transfer-Encoding": "base64",
            ]
        case .signedMessage(let boundary, _, _, _):
            return [
                "Content-Type": "multipart/signed; protocol=\"application/pkcs7-signature\"; micalg=sha-256; boundary=\"\(boundary)\"",
            ]
        }


    }

    @discardableResult
    internal func writePayload(into buffer: inout ByteBuffer) throws -> Int {
        switch self {
        case .plain(let text):
            return buffer.writeString(text)
        case .html(let html):
            return buffer.writeString(html)
        case .alternative(let boundary, let text, let html):
            let writtenBytes = buffer.writerIndex
            try MultipartSerializer().serialize(
                parts: [
                    MultipartPart(
                        headers: [
                            "Content-Type": "text/plain; charset=utf-8",
                        ],
                        body: text
                    ),
                    MultipartPart(
                        headers: [
                            "Content-Type": "text/html; charset=utf-8",
                        ],
                        body: html
                    )
                ],
                boundary: boundary,
                into: &buffer
            )
            return buffer.writerIndex - writtenBytes
        case .image(let image):
            return buffer.writeString(image.base64)
        case .attachment(let attachment):
            return buffer.writeString(attachment.base64)
        case .signedMessage(let boundary, let html, let certificate, let key):
            let writtenBytes = buffer.writerIndex
            var signBuffer = ByteBufferAllocator().buffer(capacity: 0)
            let part = MultipartPart(
                headers: [
                    "Content-Type": "text/html; charset=utf-8",
                    "Content-Transfer-Encoding": "base64"
                ],
                body: html.base64Encoded
            )
            for (key, val) in part.headers {
                signBuffer.writeString(key)
                signBuffer.writeString(": ")
                signBuffer.writeString(val)
                signBuffer.writeString("\r\n")
            }
            signBuffer.writeString("\r\n")
            var body = part.body
            signBuffer.writeBuffer(&body)
            //signBuffer.writeString("\r\n")
            signBuffer.moveReaderIndex(to: 0)
            let data = signBuffer.readData(length: signBuffer.readableBytes)!
            var alg:  Certificate.SignatureAlgorithm!

            // That's absolutely ugly, and wrong and bogus. `X509.Certificate` doesn't allow accessing the BackingPublicKey, only
            // a lame string `description`
            switch certificate.publicKey.description.prefix(3) {
            case "RSA":
                alg = .sha256WithRSAEncryption
            case "P256", "P384", "P521":
                alg = .ecdsaWithSHA256
            case "Ed2":
                alg = .ed25519
            default:
                alg = .sha1WithRSAEncryption
            }
            let signed = try X509.CMS.sign(data, signatureAlgorithm: alg, certificate: certificate, privateKey: key)
            let signedData = Data(signed)

            try MultipartSerializer().serialize(
                parts: [
                    part,
                    MultipartPart(
                        headers: [
                            "Content-Type": "application/pkcs7-signature; name=smime.p7s",
                            "Content-Disposition": "attachment; filename=smime.p7s",
                            "Content-Transfer-Encoding": "base64",
                        ],
                        body: signedData.base64EncodedString(options: .lineLength76Characters)
                    ),
                ],
                boundary: boundary,
                into: &buffer
            )
            return buffer.writerIndex - writtenBytes
        }
    }
}

extension Mail.Content {
    internal var headers: [String: String] {
        switch _content {
        case .single(let block):
            return block.headers
        case .multipart(boundary: let boundary, blocks: _):
            return [
                "Content-Type": "multipart/mixed; boundary=\(boundary)",
            ]
        }
    }

    @discardableResult
    internal func writePayload(into buffer: inout ByteBuffer) throws -> Int {
        switch _content {
        case .multipart(boundary: let boundary, blocks: let blocks):
            var written = 0
            for block in blocks {
                let headers = block.headers.map { "\($0): \($1)" }.joined(separator: "\r\n")
                written += buffer.writeString("""
                --\(boundary)\r
                \(headers)\r
                \r
                
                """)

                written += try block.writePayload(into: &buffer)
                written += buffer.writeString("\n")
            }

            return written
        case .single(let block):
            return try block.writePayload(into: &buffer)
        }
    }
}

extension Mail {
    // TODO: Attachments

    /// Generates the headers of the mail.
    internal func headers(forHost host: String) -> [String: String] {
        var headers = content.headers
        for (key, value) in customHeaders {
            headers[key] = value
        }
        headers.reserveCapacity(16)

        headers["MIME-Version"] = "1.0"
        headers["Message-Id"] = "<\(UUID().uuidString)@\(host)>"
        headers["Date"] = Date().smtpFormatted
        headers["From"] = from.smtpFormatted
        headers["To"] = to.map(\.smtpFormatted)
            .joined(separator: ", ")

        if let replyTo {
            headers["Reply-To"] = replyTo.smtpFormatted
        }

        if !cc.isEmpty {
            headers["Cc"] = cc.map { $0.smtpFormatted }
                .joined(separator: ", ")
        }

        if let data = subject.data(using: .utf8) {
            headers["Subject"] = "=?utf-8?B?\(data.base64EncodedString())?="
        } else {
            headers["Subject"] = subject
        }

        return headers
    }
}
