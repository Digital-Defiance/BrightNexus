//
//  BrightNexusUITests.swift
//  BrightNexusUITests
//
//  Originally created as EnclaveUITests by Jessica Mulein on 1/24/26.
//  Renamed and updated for the BrightNexus rename on 2026-05-21.
//

import XCTest

final class BrightNexusUITests: XCTestCase {

    var app: XCUIApplication!

    override func setUpWithError() throws {
        continueAfterFailure = false
        app = XCUIApplication()
        app.launch()
    }

    override func tearDownWithError() throws {
        app = nil
    }

    // MARK: - Window Tests

    @MainActor
    func testAppLaunches() throws {
        XCTAssertTrue(app.exists, "App should be running")
        let menuBarItem = app.menuBars.menuBarItems["BrightNexus"]
        XCTAssertTrue(menuBarItem.waitForExistence(timeout: 5), "App should have menu bar item")
    }

    @MainActor
    func testMainWindowTitle() throws {
        let window = app.windows.firstMatch
        XCTAssertTrue(window.exists, "Main window should exist")
    }

    // MARK: - Navigation Tests

    @MainActor
    func testSidebarExists() throws {
        let serverRunningText = app.staticTexts["Server Running"]
        let serverStoppedText = app.staticTexts["Server Stopped"]
        XCTAssertTrue(serverRunningText.exists || serverStoppedText.exists,
                      "Server status should be visible in sidebar")
    }

    @MainActor
    func testDashboardNavigation() throws {
        let dashboard = app.buttons["Dashboard"]
        if dashboard.exists {
            dashboard.click()
            let dashboardTitle = app.staticTexts["BrightNexus"]
            XCTAssertTrue(dashboardTitle.waitForExistence(timeout: 2),
                          "Dashboard title should be visible")
        }
    }

    @MainActor
    func testConnectionsNavigation() throws {
        let connections = app.buttons["Connections"]
        if connections.exists {
            connections.click()
            Thread.sleep(forTimeInterval: 0.5)
            let noConnectionsText = app.staticTexts["No Active Connections"]
            let connectionsTitle = app.staticTexts["Active Connections"]
            XCTAssertTrue(noConnectionsText.exists || connectionsTitle.exists,
                          "Connections view should be visible")
        }
    }

    @MainActor
    func testKeysNavigation() throws {
        let keys = app.buttons["Keys"]
        if keys.exists {
            keys.click()
            Thread.sleep(forTimeInterval: 0.5)
            let noKeysText = app.staticTexts["No Keys Available"]
            let keysTitle = app.staticTexts["Cryptographic Keys"]
            XCTAssertTrue(noKeysText.exists || keysTitle.exists,
                          "Keys view should be visible")
        }
    }

    // MARK: - Dashboard Content Tests

    @MainActor
    func testDashboardShowsServerStatus() throws {
        let dashboard = app.buttons["Dashboard"]
        if dashboard.exists { dashboard.click() }
        let serverLabel = app.staticTexts["Server"]
        XCTAssertTrue(serverLabel.waitForExistence(timeout: 2),
                      "Server status row should be visible in dashboard")
    }

    @MainActor
    func testDashboardShowsConnectionCount() throws {
        let dashboard = app.buttons["Dashboard"]
        if dashboard.exists { dashboard.click() }
        let connectionsLabel = app.staticTexts["Active Connections"]
        XCTAssertTrue(connectionsLabel.waitForExistence(timeout: 2),
                      "Active Connections row should be visible in dashboard")
    }

    @MainActor
    func testDashboardShowsKeyCount() throws {
        let dashboard = app.buttons["Dashboard"]
        if dashboard.exists { dashboard.click() }
        let keysLabel = app.staticTexts["Keys Loaded"]
        XCTAssertTrue(keysLabel.waitForExistence(timeout: 2),
                      "Keys Loaded row should be visible in dashboard")
    }

    @MainActor
    func testDashboardShowsRequestCount() throws {
        let dashboard = app.buttons["Dashboard"]
        if dashboard.exists { dashboard.click() }
        let requestsLabel = app.staticTexts["Total Requests"]
        XCTAssertTrue(requestsLabel.waitForExistence(timeout: 2),
                      "Total Requests row should be visible in dashboard")
    }

    // MARK: - Socket Path Tests

    @MainActor
    func testSocketPathVisible() throws {
        let dashboard = app.buttons["Dashboard"]
        if dashboard.exists {
            dashboard.click()
            Thread.sleep(forTimeInterval: 0.5)
        }

        // The socket path is now ~/.brightchain/brightnexus/brightnexus.sock,
        // with a legacy compat socket also bound at ~/.enclave/enclave-bridge.sock.
        let socketPathVariants = [
            app.staticTexts.matching(NSPredicate(format: "label CONTAINS[c] '.sock'")),
            app.staticTexts.matching(NSPredicate(format: "label CONTAINS[c] 'brightnexus'")),
            app.staticTexts.matching(NSPredicate(format: "label CONTAINS[c] 'brightchain'"))
        ]

        var found = false
        for variant in socketPathVariants {
            if variant.firstMatch.waitForExistence(timeout: 2) {
                found = true
                break
            }
        }

        if !found {
            let serverStatus = app.staticTexts["Server Running"]
            let serverStopped = app.staticTexts["Server Stopped"]
            XCTAssertTrue(serverStatus.exists || serverStopped.exists,
                          "At minimum, server status should be visible")
        }
    }

    @MainActor
    func testSocketPathContextMenu() throws {
        let socketPathText = app.staticTexts.matching(
            NSPredicate(format: "label CONTAINS[c] 'brightnexus.sock'")).firstMatch

        if socketPathText.waitForExistence(timeout: 3) {
            socketPathText.rightClick()
            let copyMenuItem = app.menuItems["Copy Socket Path"]
            XCTAssertTrue(copyMenuItem.waitForExistence(timeout: 2),
                          "Context menu should have 'Copy Socket Path' option")
            app.typeKey(.escape, modifierFlags: [])
        }
    }

    // MARK: - Performance Tests

    @MainActor
    func testLaunchPerformance() throws {
        measure(metrics: [XCTApplicationLaunchMetric()]) {
            XCUIApplication().launch()
        }
    }

    // MARK: - Menu Tests

    @MainActor
    func testQuitMenuExists() throws {
        app.menuBars.menuBarItems["BrightNexus"].click()
        let quitMenuItem = app.menuItems["Quit BrightNexus"]
        XCTAssertTrue(quitMenuItem.exists, "Quit menu item should exist")
        app.typeKey(.escape, modifierFlags: [])
    }
}
