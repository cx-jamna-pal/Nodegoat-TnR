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

  // Security regression tests: verify code injection via eval() is no longer possible
  describe("Code injection prevention (CWE-94)", () => {

    it("Should reject a JavaScript expression injected as preTax value", () => {
      // An attacker might submit a JS expression that eval() would execute.
      // parseInt() should parse this as NaN, triggering the validation error.
      cy.userSignIn();
      cy.visitPage("/contributions");

      cy.get("table").find("input").eq(0).clear().type("1+1");
      cy.get("table").find("input").eq(1).clear().type("5");
      cy.get("table").find("input").eq(2).clear().type("5");

      cy.get("button[type='submit']").click();

      // The server should reject the non-integer input and display a validation error
      cy.get(".alert-danger, .alert-error, [class*='error'], [class*='alert']")
        .should("be.visible")
        .and("contain", "Invalid");

      cy.url().should("include", "contributions");
    });

    it("Should reject a JavaScript function call injected as afterTax value", () => {
      // Simulates an attempt to call a function via eval(); parseInt() returns NaN for this
      cy.userSignIn();
      cy.visitPage("/contributions");

      cy.get("table").find("input").eq(0).clear().type("5");
      cy.get("table").find("input").eq(1).clear().type("process.exit(0)");
      cy.get("table").find("input").eq(2).clear().type("5");

      cy.get("button[type='submit']").click();

      cy.get(".alert-danger, .alert-error, [class*='error'], [class*='alert']")
        .should("be.visible")
        .and("contain", "Invalid");

      cy.url().should("include", "contributions");
    });

    it("Should reject a JavaScript object access expression injected as roth value", () => {
      // Simulates an attempt to access server-side globals via eval()
      cy.userSignIn();
      cy.visitPage("/contributions");

      cy.get("table").find("input").eq(0).clear().type("5");
      cy.get("table").find("input").eq(1).clear().type("5");
      cy.get("table").find("input").eq(2).clear().type("require('os').platform()");

      cy.get("button[type='submit']").click();

      cy.get(".alert-danger, .alert-error, [class*='error'], [class*='alert']")
        .should("be.visible")
        .and("contain", "Invalid");

      cy.url().should("include", "contributions");
    });

    it("Should accept valid integer contribution percentages", () => {
      // Ensures the fix does not break legitimate numeric submissions
      cy.userSignIn();
      cy.visitPage("/contributions");

      cy.get("table").find("input").eq(0).clear().type("5");
      cy.get("table").find("input").eq(1).clear().type("5");
      cy.get("table").find("input").eq(2).clear().type("5");

      cy.get("button[type='submit']").click();

      cy.get(".alert-success").should("be.visible");
      cy.url().should("include", "contributions");
    });

    it("Should accept zero as a valid contribution percentage", () => {
      // Edge case: zero is a valid integer and should be accepted
      cy.userSignIn();
      cy.visitPage("/contributions");

      cy.get("table").find("input").eq(0).clear().type("0");
      cy.get("table").find("input").eq(1).clear().type("0");
      cy.get("table").find("input").eq(2).clear().type("0");

      cy.get("button[type='submit']").click();

      cy.get(".alert-success").should("be.visible");
      cy.url().should("include", "contributions");
    });

    it("Should reject negative contribution percentages", () => {
      // Negative values fail the < 0 validation check
      cy.userSignIn();
      cy.visitPage("/contributions");

      cy.get("table").find("input").eq(0).clear().type("-1");
      cy.get("table").find("input").eq(1).clear().type("5");
      cy.get("table").find("input").eq(2).clear().type("5");

      cy.get("button[type='submit']").click();

      cy.get(".alert-danger, .alert-error, [class*='error'], [class*='alert']")
        .should("be.visible")
        .and("contain", "Invalid");

      cy.url().should("include", "contributions");
    });

    it("Should reject contributions that exceed 30 percent in total", () => {
      // Validates the 30% total cap is still enforced after the fix
      cy.userSignIn();
      cy.visitPage("/contributions");

      cy.get("table").find("input").eq(0).clear().type("20");
      cy.get("table").find("input").eq(1).clear().type("10");
      cy.get("table").find("input").eq(2).clear().type("5");

      cy.get("button[type='submit']").click();

      cy.get(".alert-danger, .alert-error, [class*='error'], [class*='alert']")
        .should("be.visible")
        .and("contain", "30");

      cy.url().should("include", "contributions");
    });

  });
});
