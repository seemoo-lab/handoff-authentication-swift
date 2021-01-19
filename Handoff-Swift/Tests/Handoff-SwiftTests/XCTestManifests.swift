import XCTest

#if !canImport(ObjectiveC)
public func allTests() -> [XCTestCaseEntry] {
    return [
        testCase(Handoff_SwiftTests.allTests),
    ]
}
#endif
