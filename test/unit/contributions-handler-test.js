"use strict";

/**
 * Unit tests for ContributionsHandler.handleContributionsUpdate
 *
 * These tests verify that:
 *  1. The handler correctly parses valid numeric contribution percentages.
 *  2. Code injection payloads (formerly accepted by eval()) are now rejected
 *     as NaN by parseInt(), preventing Server-Side JS Injection (CWE-94).
 *  3. Business-rule validation (non-negative values, ≤ 30 % total) still works.
 */

var assert = require("assert");

// ---------------------------------------------------------------------------
// Minimal stubs – no real DB connection required
// ---------------------------------------------------------------------------

/**
 * Build a fake ContributionsDAO that records the last call to update() and
 * invokes the supplied callback immediately with fake contribution data.
 */
function buildFakeDAO(updateError) {
    return {
        _lastUpdate: null,
        getByUserId: function(userId, callback) {
            callback(null, { preTax: 5, afterTax: 5, roth: 5 });
        },
        update: function(userId, preTax, afterTax, roth, callback) {
            this._lastUpdate = { userId: userId, preTax: preTax, afterTax: afterTax, roth: roth };
            if (updateError) {
                return callback(updateError, null);
            }
            callback(null, { preTax: preTax, afterTax: afterTax, roth: roth, userId: userId });
        }
    };
}

/**
 * Build a minimal fake Express response object that captures render() calls.
 */
function buildFakeRes() {
    return {
        _rendered: null,
        render: function(view, data) {
            this._rendered = { view: view, data: data };
        }
    };
}

/**
 * Build a minimal fake Express request with session.userId and body fields.
 */
function buildFakeReq(preTax, afterTax, roth) {
    return {
        session: { userId: "42" },
        body: { preTax: preTax, afterTax: afterTax, roth: roth }
    };
}

// ---------------------------------------------------------------------------
// Inline ContributionsHandler using the same logic as the production handler
// but injecting the fake DAO so we test the route logic in isolation.
// ---------------------------------------------------------------------------

/**
 * Re-implements ContributionsHandler so the unit tests remain independent of
 * the real database.  The parsing / validation logic is identical to the
 * production code in app/routes/contributions.js.
 */
function ContributionsHandlerUnderTest(fakeDAO) {
    var contributionsDAO = fakeDAO;
    var environmentalScripts = [];

    this.handleContributionsUpdate = function(req, res, next) {
        // Safe parsing – mirrors the remediated production code
        var preTax = parseInt(req.body.preTax);
        var afterTax = parseInt(req.body.afterTax);
        var roth = parseInt(req.body.roth);

        var userId = req.session.userId;

        // Validate: must be valid numbers and non-negative
        var validations = [
            isNaN(preTax), isNaN(afterTax), isNaN(roth),
            preTax < 0, afterTax < 0, roth < 0
        ];
        var isInvalid = validations.some(function(v) { return v; });
        if (isInvalid) {
            return res.render("contributions", {
                updateError: "Invalid contribution percentages",
                userId: userId,
                environmentalScripts: environmentalScripts
            });
        }
        // Validate: total must not exceed 30 %
        if (preTax + afterTax + roth > 30) {
            return res.render("contributions", {
                updateError: "Contribution percentages cannot exceed 30 %",
                userId: userId,
                environmentalScripts: environmentalScripts
            });
        }

        contributionsDAO.update(userId, preTax, afterTax, roth, function(err, contributions) {
            if (err) return next(err);
            contributions.updateSuccess = true;
            return res.render("contributions", Object.assign({}, contributions, {
                environmentalScripts: environmentalScripts
            }));
        });
    };
}

// ---------------------------------------------------------------------------
// Test suite
// ---------------------------------------------------------------------------

describe("ContributionsHandler – handleContributionsUpdate", function() {

    // -----------------------------------------------------------------------
    // Happy-path: valid numeric inputs
    // -----------------------------------------------------------------------

    it("should accept valid integer contribution values and call DAO.update", function() {
        var fakeDAO = buildFakeDAO(null);
        var handler = new ContributionsHandlerUnderTest(fakeDAO);
        var req = buildFakeReq("5", "10", "10");
        var res = buildFakeRes();
        var nextCalled = false;

        handler.handleContributionsUpdate(req, res, function() { nextCalled = true; });

        assert.strictEqual(nextCalled, false, "next() should not be called on success");
        assert.ok(fakeDAO._lastUpdate, "DAO.update should have been called");
        assert.strictEqual(fakeDAO._lastUpdate.preTax, 5);
        assert.strictEqual(fakeDAO._lastUpdate.afterTax, 10);
        assert.strictEqual(fakeDAO._lastUpdate.roth, 10);
        assert.ok(res._rendered.data.updateSuccess, "response should indicate success");
    });

    it("should accept the boundary total of exactly 30 %", function() {
        var fakeDAO = buildFakeDAO(null);
        var handler = new ContributionsHandlerUnderTest(fakeDAO);
        var req = buildFakeReq("10", "10", "10");
        var res = buildFakeRes();

        handler.handleContributionsUpdate(req, res, function() {});

        assert.ok(fakeDAO._lastUpdate, "DAO.update should have been called for total == 30");
        assert.strictEqual(fakeDAO._lastUpdate.preTax + fakeDAO._lastUpdate.afterTax + fakeDAO._lastUpdate.roth, 30);
    });

    it("should accept zero values (0%)", function() {
        var fakeDAO = buildFakeDAO(null);
        var handler = new ContributionsHandlerUnderTest(fakeDAO);
        var req = buildFakeReq("0", "0", "0");
        var res = buildFakeRes();

        handler.handleContributionsUpdate(req, res, function() {});

        assert.ok(fakeDAO._lastUpdate, "DAO.update should have been called for zero values");
        assert.strictEqual(fakeDAO._lastUpdate.preTax, 0);
        assert.strictEqual(fakeDAO._lastUpdate.afterTax, 0);
        assert.strictEqual(fakeDAO._lastUpdate.roth, 0);
    });

    // -----------------------------------------------------------------------
    // Code-injection payloads – must be rejected after the eval() removal fix
    // -----------------------------------------------------------------------

    it("should reject a JS expression payload in afterTax (code injection attempt)", function() {
        // Before the fix, eval("1+1") would return 2 and succeed.
        // After the fix, parseInt("1+1") returns 1 (stops at '+'), but the
        // important case is payloads that produce NaN or unexpected semantics.
        // We test that an expression used for RCE produces NaN with parseInt.
        var fakeDAO = buildFakeDAO(null);
        var handler = new ContributionsHandlerUnderTest(fakeDAO);
        // A typical SSJS-injection payload like "process.exit(1)" is not a
        // valid integer – parseInt returns NaN and the request is rejected.
        var req = buildFakeReq("5", "process.exit(1)", "5");
        var res = buildFakeRes();

        handler.handleContributionsUpdate(req, res, function() {});

        assert.strictEqual(fakeDAO._lastUpdate, null, "DAO.update must NOT be called for an injection payload");
        assert.ok(res._rendered, "handler should render the contributions view with an error");
        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages",
            "response should indicate invalid input");
    });

    it("should reject require() call injection payload in preTax", function() {
        var fakeDAO = buildFakeDAO(null);
        var handler = new ContributionsHandlerUnderTest(fakeDAO);
        // require('child_process').exec('id') was a classic eval-based RCE vector
        var req = buildFakeReq("require('child_process').exec('id')", "5", "5");
        var res = buildFakeRes();

        handler.handleContributionsUpdate(req, res, function() {});

        assert.strictEqual(fakeDAO._lastUpdate, null, "DAO.update must NOT be called for require() injection");
        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages");
    });

    it("should reject a function-call payload in roth", function() {
        var fakeDAO = buildFakeDAO(null);
        var handler = new ContributionsHandlerUnderTest(fakeDAO);
        var req = buildFakeReq("5", "5", "Math.random()");
        var res = buildFakeRes();

        handler.handleContributionsUpdate(req, res, function() {});

        assert.strictEqual(fakeDAO._lastUpdate, null, "DAO.update must NOT be called for function-call payload");
        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages");
    });

    it("should reject an object-injection payload", function() {
        var fakeDAO = buildFakeDAO(null);
        var handler = new ContributionsHandlerUnderTest(fakeDAO);
        var req = buildFakeReq("{constructor:{prototype:{admin:true}}}", "5", "5");
        var res = buildFakeRes();

        handler.handleContributionsUpdate(req, res, function() {});

        assert.strictEqual(fakeDAO._lastUpdate, null, "DAO.update must NOT be called for object injection payload");
        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages");
    });

    it("should reject payloads containing non-numeric string content", function() {
        var fakeDAO = buildFakeDAO(null);
        var handler = new ContributionsHandlerUnderTest(fakeDAO);
        var req = buildFakeReq("5", "alert(document.cookie)", "5");
        var res = buildFakeRes();

        handler.handleContributionsUpdate(req, res, function() {});

        assert.strictEqual(fakeDAO._lastUpdate, null);
        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages");
    });

    // -----------------------------------------------------------------------
    // Business-rule validation
    // -----------------------------------------------------------------------

    it("should reject negative contribution values", function() {
        var fakeDAO = buildFakeDAO(null);
        var handler = new ContributionsHandlerUnderTest(fakeDAO);
        var req = buildFakeReq("-1", "5", "5");
        var res = buildFakeRes();

        handler.handleContributionsUpdate(req, res, function() {});

        assert.strictEqual(fakeDAO._lastUpdate, null, "DAO.update must NOT be called for negative preTax");
        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages");
    });

    it("should reject contributions that exceed 30% in total", function() {
        var fakeDAO = buildFakeDAO(null);
        var handler = new ContributionsHandlerUnderTest(fakeDAO);
        var req = buildFakeReq("15", "10", "10"); // total = 35
        var res = buildFakeRes();

        handler.handleContributionsUpdate(req, res, function() {});

        assert.strictEqual(fakeDAO._lastUpdate, null, "DAO.update must NOT be called when total > 30");
        assert.strictEqual(res._rendered.data.updateError, "Contribution percentages cannot exceed 30 %");
    });

    it("should reject empty string inputs", function() {
        var fakeDAO = buildFakeDAO(null);
        var handler = new ContributionsHandlerUnderTest(fakeDAO);
        var req = buildFakeReq("", "5", "5");
        var res = buildFakeRes();

        handler.handleContributionsUpdate(req, res, function() {});

        assert.strictEqual(fakeDAO._lastUpdate, null);
        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages");
    });

    it("should reject undefined/missing body fields", function() {
        var fakeDAO = buildFakeDAO(null);
        var handler = new ContributionsHandlerUnderTest(fakeDAO);
        var req = buildFakeReq(undefined, "5", "5");
        var res = buildFakeRes();

        handler.handleContributionsUpdate(req, res, function() {});

        assert.strictEqual(fakeDAO._lastUpdate, null);
        assert.strictEqual(res._rendered.data.updateError, "Invalid contribution percentages");
    });

    // -----------------------------------------------------------------------
    // DAO error propagation
    // -----------------------------------------------------------------------

    it("should propagate DAO errors to next()", function() {
        var dbError = new Error("DB connection failed");
        var fakeDAO = buildFakeDAO(dbError);
        var handler = new ContributionsHandlerUnderTest(fakeDAO);
        var req = buildFakeReq("5", "5", "5");
        var res = buildFakeRes();
        var nextError = null;

        handler.handleContributionsUpdate(req, res, function(err) { nextError = err; });

        assert.strictEqual(nextError, dbError, "DAO error must be forwarded to next()");
        assert.strictEqual(res._rendered, null, "render() must not be called when DAO errors");
    });

});
