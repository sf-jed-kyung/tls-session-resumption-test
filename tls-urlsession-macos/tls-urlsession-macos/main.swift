import Foundation
import Network

var session: URLSession
var task: URLSessionWebSocketTask

let config = URLSessionConfiguration.default
config.tlsMinimumSupportedProtocolVersion = .TLSv12
config.tlsMaximumSupportedProtocolVersion = .TLSv13
config.httpMaximumConnectionsPerHost = 1
session = URLSession(configuration: config)

let tlsOptions = NWProtocolTLS.Options()
sec_protocol_options_set_tls_tickets_enabled(tlsOptions.securityProtocolOptions, true)
sec_protocol_options_set_tls_resumption_enabled(tlsOptions.securityProtocolOptions, true)

let url = URL(string: "wss://echo.websocket.events")!

task = session.webSocketTask(with: url)

Task {
    do {
        let message = try await task.receive()
        try Task.checkCancellation() // Check if task is cancelled before delegate call
        
        switch message {
        case .data:
            print("1 Received data")
            break
        case .string(let string):
            print("1 Received string: \(string)")
        default:
        break
        }
    } catch {
        // TODO: fail error call infinitely in some debug case
        // if code 57 (socket not connected, abort listen)
        print("1 Error: \(error)")
        return
    }
}

task.resume()

Thread.sleep(forTimeInterval: 2)

task.cancel()

task = session.webSocketTask(with: url)

Task {
    do {
        let message = try await task.receive()
        try Task.checkCancellation() // Check if task is cancelled before delegate call
        
        switch message {
        case .data:
            print("2 Received data")// \(String(data: unzipped, encoding: .utf8))")
            break
        case .string(let string):
            print("2 Received string: \(string)")
        default:
            break
        }
    } catch {
        // TODO: fail error call infinitely in some debug case
        // if code 57 (socket not connected, abort listen)
        print("2 Error: \(error)")
        return
    }
}

task.resume()

Thread.sleep(forTimeInterval: 2)

task.cancel()

// Keep the main thread alive to listen for messages
RunLoop.main.run()
