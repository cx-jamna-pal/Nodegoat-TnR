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

  // Security regression tests for CWE-94: Code Injection via eval()
  // These tests verify that user-controlled input is NOT executed as code
  // and that parseInt() is used safely instead of eval().

  it("Should reject non-numeric preTax input and not execute it as code", () => {
    // Attempting to inject JS code via preTax field - must not be executed
    cy.userSignIn();
    cy.visitPage("/contributions");
    cy.get("table")
      .find("input")
      .eq(0)
      .clear()
      .type("1+1");

    cy.get("button[type='submit']").click();

    // With parseInt(), "1+1" parses to NaN or 1 (not 2), and the app should
    // show a validation error, NOT update the contribution with the eval'd result.
    // The page should NOT show a success message for an injected expression.
    cy.get(".alert-success").should("not.exist");
    cy.url().should("include", "contributions");
  });

  it("Should reject JavaScript expression injection in afterTax field", () => {
    // Attempting to inject an arithmetic JS expression - parseInt() should return NaN
    cy.userSignIn();
    cy.visitPage("/contributions");
    cy.get("table")
      .find("input")
      .eq(1)
      .clear()
      .type("5*2");

    cy.get("button[type='submit']").click();

    // parseInt("5*2") returns 5 (only leading integer), not 10 (as eval would)
    // The form submission should not succeed with injected expression values
    cy.get(".alert-success").should("not.exist");
    cy.url().should("include", "contributions");
  });

  it("Should reject code injection payload in roth field", () => {
    // Attempting to inject a JS expression via roth field - parseInt() returns NaN
    cy.userSignIn();
    cy.visitPage("/contributions");
    cy.get("table")
      .find("input")
      .eq(2)
      .clear()
      .type("process.exit(1)");

    cy.get("button[type='submit']").click();

    // parseInt("process.exit(1)") returns NaN, triggering validation error
    cy.get(".alert-success").should("not.exist");
    cy.url().should("include", "contributions");
  });

  it("Should accept valid integer contribution values and save successfully", () => {
    // Verify that legitimate numeric input still works correctly after fix
    cy.userSignIn();
    cy.visitPage("/contributions");

    const inputs = cy.get("table").find("input");
    inputs.eq(0).clear().type("5");
    inputs.eq(1).clear().type("5");
    inputs.eq(2).clear().type("5");

    cy.get("button[type='submit']").click();

    cy.get(".alert-success").should("be.visible");
    cy.url().should("include", "contributions");
  });

  it("Should reject contributions that exceed 30% total", () => {
    // Validate existing business rule still works with parseInt-based parsing
    cy.userSignIn();
    cy.visitPage("/contributions");

    const inputs = cy.get("table").find("input");
    inputs.eq(0).clear().type("11");
    inputs.eq(1).clear().type("11");
    inputs.eq(2).clear().type("11");

    cy.get("button[type='submit']").click();

    cy.get(".alert-danger, .alert-warning, [class*='error']")
      .should("be.visible");
    cy.get(".alert-success").should("not.exist");
  });

  it("Should reject negative contribution values", () => {
    // Validate existing negative-value guard still works
    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table")
      .find("input")
      .first()
      .clear()
      .type("-5");

    cy.get("button[type='submit']").click();

    cy.get(".alert-success").should("not.exist");
    cy.url().should("include", "contributions");
  });
});
