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

  // Security regression tests for CWE-94 Code Injection (SSJS Injection)
  // These tests verify that eval() has been replaced with parseInt() and
  // that arbitrary JavaScript expressions in contribution fields are rejected.

  it("Should reject JavaScript expression injection in preTax field", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    // Attempt to inject a JS expression via the preTax field (previously executed by eval())
    cy.get("table").find("input").eq(0).clear().type("1+1");
    cy.get("table").find("input").eq(1).clear().type("5");
    cy.get("table").find("input").eq(2).clear().type("5");

    cy.get("button[type='submit']").click();

    // With parseInt(), "1+1" is parsed as NaN (parseInt does not evaluate expressions),
    // so the server should return a validation error, not execute code or accept the value.
    cy.get(".alert-danger, .text-danger, [class*='error']")
      .should("exist");

    cy.url().should("include", "contributions");
  });

  it("Should reject JavaScript expression injection in afterTax field", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    // Attempt to inject a JS expression via the afterTax field
    cy.get("table").find("input").eq(0).clear().type("5");
    cy.get("table").find("input").eq(1).clear().type("1+1");
    cy.get("table").find("input").eq(2).clear().type("5");

    cy.get("button[type='submit']").click();

    // "1+1" is not a valid integer literal, so parseInt returns NaN → validation error
    cy.get(".alert-danger, .text-danger, [class*='error']")
      .should("exist");

    cy.url().should("include", "contributions");
  });

  it("Should reject JavaScript expression injection in roth field", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    // Attempt to inject a JS expression via the roth field
    cy.get("table").find("input").eq(0).clear().type("5");
    cy.get("table").find("input").eq(1).clear().type("5");
    cy.get("table").find("input").eq(2).clear().type("1+1");

    cy.get("button[type='submit']").click();

    // "1+1" is not a valid integer literal; parseInt returns NaN → validation error
    cy.get(".alert-danger, .text-danger, [class*='error']")
      .should("exist");

    cy.url().should("include", "contributions");
  });

  it("Should reject process.exit() code injection payload in contribution fields", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    // Attempt a destructive code injection payload via the preTax field
    cy.get("table").find("input").eq(0).clear().type("process.exit(1)");
    cy.get("table").find("input").eq(1).clear().type("5");
    cy.get("table").find("input").eq(2).clear().type("5");

    cy.get("button[type='submit']").click();

    // The server must still be running (not crashed) and return a validation error.
    // parseInt("process.exit(1)") → NaN, so the validation check blocks it.
    cy.get(".alert-danger, .text-danger, [class*='error']")
      .should("exist");

    // Confirm the application is still alive and responsive
    cy.url().should("include", "contributions");
  });

  it("Should accept valid integer contribution values", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table").find("input").eq(0).clear().type("5");
    cy.get("table").find("input").eq(1).clear().type("10");
    cy.get("table").find("input").eq(2).clear().type("10");

    cy.get("button[type='submit']").click();

    cy.get(".alert-success").should("be.visible");
    cy.url().should("include", "contributions");
  });

  it("Should reject negative contribution values", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table").find("input").eq(0).clear().type("-1");
    cy.get("table").find("input").eq(1).clear().type("5");
    cy.get("table").find("input").eq(2).clear().type("5");

    cy.get("button[type='submit']").click();

    cy.get(".alert-danger, .text-danger, [class*='error']")
      .should("exist");
  });

  it("Should reject contributions exceeding 30% total", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table").find("input").eq(0).clear().type("15");
    cy.get("table").find("input").eq(1).clear().type("10");
    cy.get("table").find("input").eq(2).clear().type("10");

    cy.get("button[type='submit']").click();

    cy.get(".alert-danger, .text-danger, [class*='error']")
      .should("exist");
  });
});
