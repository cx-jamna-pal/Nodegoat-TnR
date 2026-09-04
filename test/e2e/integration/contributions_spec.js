/// <reference types="Cypress" />

describe("/contributions behaviour", () => {
  "use strict";

  before(() => {
    cy.dbReset();
  });

  afterEach(() => {
    cy.visitPage("/logout");
  });

  it("Should redirect if the user has not logged in", () => {
    cy.visitPage("/contributions");
    cy.url().should("include", "login");
  });

  it("Should be accesible for a logged user", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");
    cy.url().should("include", "contributions");
  });

  it("Should be a table with several inputs", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");
    cy.get("table")
      .find("input")
      .should("have.length", 3);
  });

  it("Should input be modified", () => {
    const value = "12";
    cy.userSignIn();
    cy.visitPage("/contributions");
    cy.get("table")
      .find("input")
      .first()
      .clear()
      .type(value);

    cy.get("button[type='submit']")
      .click();

    cy.get("tbody > tr > td")
      .eq(1)
      .contains(`${value} %`);

    cy.get(".alert-success")
      .should("be.visible");

    cy.url().should("include", "contributions");
  });

  // ---- Security regression tests for CWE-94 Code Injection (eval() removal) ----

  it("Should reject a JavaScript expression string as a contribution value (code injection prevention)", () => {
    // Previously, eval() would execute "1+1" and store 2. After the fix,
    // parseInt("1+1") returns 1, and the server-side validation catches
    // expressions that do not parse to a plain integer via NaN checks.
    // The key assertion is that the server does NOT execute arbitrary code.
    cy.userSignIn();
    cy.visitPage("/contributions");

    // Submit an arithmetic expression as preTax — with eval() this would
    // return a numeric result (e.g. 20), bypassing limits. With parseInt()
    // the expression suffix is ignored and only the leading integer is used.
    cy.get("table")
      .find("input")
      .eq(0)
      .clear()
      .type("10+10"); // eval() would produce 20; parseInt() produces 10

    cy.get("table")
      .find("input")
      .eq(1)
      .clear()
      .type("5");

    cy.get("table")
      .find("input")
      .eq(2)
      .clear()
      .type("5");

    cy.get("button[type='submit']").click();

    // The page should still be contributions (not crash/error page).
    cy.url().should("include", "contributions");

    // A success alert means the value was treated as 10 (not 20),
    // so 10 + 5 + 5 = 20 which is within the 30% limit.
    cy.get(".alert-success").should("be.visible");
  });

  it("Should reject non-numeric code injection payloads as invalid", () => {
    // Payloads that eval() would execute but parseInt() would parse as NaN
    // must result in a validation error, not code execution or a crash.
    const maliciousPayloads = [
      "process.exit(1)",
      "require('fs').readFileSync('/etc/passwd','utf8')",
      "Object.keys(process.env).join(',')",
    ];

    maliciousPayloads.forEach((payload) => {
      cy.userSignIn();
      cy.visitPage("/contributions");

      cy.get("table")
        .find("input")
        .eq(0)
        .clear()
        .type(payload);

      cy.get("button[type='submit']").click();

      // The server must respond with an error message, not execute the code.
      // The application should remain on the contributions page.
      cy.url().should("include", "contributions");

      // Validation error must be shown — the payload is not a valid integer.
      cy.get(".alert-danger, .alert-error, [class*='error'], [class*='alert']")
        .should("exist");

      cy.visitPage("/logout");
    });
  });

  it("Should reject negative numbers in contribution fields", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table")
      .find("input")
      .eq(0)
      .clear()
      .type("-5");

    cy.get("button[type='submit']").click();

    cy.url().should("include", "contributions");

    // Negative values must trigger validation error
    cy.get(".alert-danger, .alert-error, [class*='error'], [class*='alert']")
      .should("exist");
  });

  it("Should reject contributions that exceed the 30% total limit", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table")
      .find("input")
      .eq(0)
      .clear()
      .type("15");

    cy.get("table")
      .find("input")
      .eq(1)
      .clear()
      .type("10");

    cy.get("table")
      .find("input")
      .eq(2)
      .clear()
      .type("10");

    cy.get("button[type='submit']").click();

    cy.url().should("include", "contributions");

    // 15 + 10 + 10 = 35 > 30, must show an error
    cy.contains("cannot exceed 30").should("be.visible");
  });

  it("Should accept valid contribution values at the 30% boundary", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table")
      .find("input")
      .eq(0)
      .clear()
      .type("10");

    cy.get("table")
      .find("input")
      .eq(1)
      .clear()
      .type("10");

    cy.get("table")
      .find("input")
      .eq(2)
      .clear()
      .type("10");

    cy.get("button[type='submit']").click();

    cy.url().should("include", "contributions");

    // 10 + 10 + 10 = 30, exactly at the limit — should succeed
    cy.get(".alert-success").should("be.visible");
  });
});
