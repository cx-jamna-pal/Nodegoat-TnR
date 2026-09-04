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

  // Security regression tests: ensure code injection via eval() is not possible (CWE-94)
  it("Should reject JavaScript expression injection in preTax field", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    // Attempt to inject a JS expression that would evaluate to a large number via eval()
    cy.get("table")
      .find("input")
      .eq(0)
      .clear()
      .type("1+1");

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

    cy.get("button[type='submit']")
      .click();

    // With parseInt(), "1+1" becomes NaN (parseInt stops at "+"), so the update
    // should be rejected with a validation error, not silently succeed
    cy.get(".alert-danger, .alert-error, [class*='error'], [class*='danger']")
      .should("be.visible");

    cy.url().should("include", "contributions");
  });

  it("Should reject non-numeric input in contribution fields", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table")
      .find("input")
      .eq(0)
      .clear()
      .type("abc");

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

    cy.get("button[type='submit']")
      .click();

    // Non-numeric input should produce a validation error
    cy.get(".alert-danger, .alert-error, [class*='error'], [class*='danger']")
      .should("be.visible");
  });

  it("Should reject negative contribution percentages", () => {
    cy.userSignIn();
    cy.visitPage("/contributions");

    cy.get("table")
      .find("input")
      .eq(0)
      .clear()
      .type("-5");

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

    cy.get("button[type='submit']")
      .click();

    // Negative values should produce a validation error
    cy.get(".alert-danger, .alert-error, [class*='error'], [class*='danger']")
      .should("be.visible");
  });

  it("Should reject contributions exceeding 30% total", () => {
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

    cy.get("button[type='submit']")
      .click();

    // Sum > 30 should produce a validation error
    cy.get(".alert-danger, .alert-error, [class*='error'], [class*='danger']")
      .should("be.visible");

    cy.get("body").should("contain", "30");
  });

  it("Should accept valid contribution percentages within limit", () => {
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

    cy.get("button[type='submit']")
      .click();

    cy.get(".alert-success")
      .should("be.visible");

    cy.url().should("include", "contributions");
  });
});
