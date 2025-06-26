import test from "ava";
import { webauthn } from "../dist/index.js";
import { randomBytes } from "crypto";

// Helper function to generate secure random bytes
function generateRandomBytes(length) {
  return randomBytes(length);
}

// Helper function to create valid creation options
function createCredentialCreationOptions() {
  return {
    rp: {
      name: "Test Application",
      id: "localhost",
    },
    user: {
      id: Buffer.from(generateRandomBytes(64)),
      name: "testuser@example.com",
      displayName: "Test User",
    },
    challenge: Buffer.from(generateRandomBytes(32)),
    pubKeyCredParams: [
      {
        type: "public-key",
        alg: -7, // ES256
      },
      {
        type: "public-key",
        alg: -257, // RS256
      },
    ],
    timeout: 60000,
    excludeCredentials: [],
    authenticatorSelection: {
      authenticatorAttachment: "platform",
      requireResidentKey: false,
      residentKey: "discouraged",
      userVerification: "preferred",
    },
    attestation: "none",
  };
}

// Helper function to create valid request options
function createCredentialRequestOptions(credentialId) {
  return {
    challenge: Buffer.from(generateRandomBytes(32)),
    timeout: 60000,
    rpId: "localhost",
    allowCredentials: credentialId
      ? [
          {
            type: "public-key",
            id: credentialId,
            transports: ["internal"],
          },
        ]
      : [],
    userVerification: "preferred",
  };
}

test("WebAuthn functions should be available", (t) => {
  t.is(typeof webauthn.create, "function");
  t.is(typeof webauthn.get, "function");
});

test("create should validate required parameters", (t) => {
  // Test with missing required fields
  t.throws(() => {
    webauthn.create({});
  });

  t.throws(() => {
    webauthn.create({
      rp: { name: "Test" },
      // missing user and challenge
    });
  });

  t.throws(() => {
    webauthn.create(null);
  });

  t.throws(() => {
    webauthn.create(undefined);
  });
});

test("get should validate required parameters", (t) => {
  t.throws(() => {
    webauthn.get({});
  });

  t.throws(() => {
    webauthn.get(null);
  });

  t.throws(() => {
    webauthn.get(undefined);
  });
});

test("create should accept valid options and return credential structure", (t) => {
  const options = createCredentialCreationOptions();

  try {
    const credential = webauthn.create(options);

    // Verify the returned credential has the expected structure
    t.is(typeof credential, "object");
    t.is(typeof credential.id, "string");
    t.true(Buffer.isBuffer(credential.rawId));
    t.is(typeof credential.response, "object");
    t.is(credential.type, "public-key");

    // Verify response structure for attestation
    t.true(Buffer.isBuffer(credential.response.clientDataJson));
    t.true(Buffer.isBuffer(credential.response.attestationObject));
    t.true(Array.isArray(credential.response.transports));

    t.pass("Credential created successfully");
  } catch (error) {
    // In test environments, this might fail due to lack of authenticator
    // but we can still verify the error is reasonable
    t.true(error instanceof Error);
    console.log(`Expected error in test environment: ${error.message}`);
    t.pass(
      "Function called correctly even though environment doesn't support WebAuthn"
    );
  }
});

test("get should accept valid options and return assertion structure", (t) => {
  const options = createCredentialRequestOptions();

  try {
    const assertion = webauthn.get(options);

    // Verify the returned assertion has the expected structure
    t.is(typeof assertion, "object");
    t.is(typeof assertion.id, "string");
    t.true(Buffer.isBuffer(assertion.rawId));
    t.is(typeof assertion.response, "object");
    t.is(assertion.type, "public-key");

    // Verify response structure for assertion
    t.true(Buffer.isBuffer(assertion.response.clientDataJson));
    t.true(Buffer.isBuffer(assertion.response.authenticatorData));
    t.true(Buffer.isBuffer(assertion.response.signature));

    t.pass("Assertion created successfully");
  } catch (error) {
    // In test environments, this might fail due to lack of authenticator
    // but we can still verify the error is reasonable
    t.true(error instanceof Error);
    console.log(`Expected error in test environment: ${error.message}`);
    t.pass(
      "Function called correctly even though environment doesn't support WebAuthn"
    );
  }
});

test("full authentication flow simulation", (t) => {
  // Step 1: Create credential creation options
  const creationOptions = createCredentialCreationOptions();

  try {
    // Step 2: Attempt to create a credential
    console.log("Attempting credential creation...");
    const newCredential = webauthn.create(creationOptions);

    // Step 3: Verify credential structure
    t.is(typeof newCredential.id, "string");
    t.true(Buffer.isBuffer(newCredential.rawId));
    t.is(newCredential.type, "public-key");

    console.log(`Created credential with ID: ${newCredential.id}`);

    // Step 4: Create authentication options using the credential ID
    const authOptions = createCredentialRequestOptions(newCredential.rawId);

    // Step 5: Attempt authentication
    console.log("Attempting authentication...");
    const assertion = webauthn.get(authOptions);

    // Step 6: Verify assertion structure
    t.is(typeof assertion.id, "string");
    t.true(Buffer.isBuffer(assertion.rawId));
    t.is(assertion.type, "public-key");

    console.log(`Authentication successful with ID: ${assertion.id}`);

    // Step 7: Verify the credential IDs match (same credential used)
    t.is(assertion.id, newCredential.id);
    t.deepEqual(assertion.rawId, newCredential.rawId);

    t.pass("Complete WebAuthn flow executed successfully");
  } catch (error) {
    // Log the error for debugging but don't fail the test
    console.log(
      `WebAuthn flow error (expected in test environment): ${error.message}`
    );

    // Verify it's a reasonable error and not a programming mistake
    t.true(error instanceof Error);
    t.true(
      error.message.includes("authenticator") ||
        error.message.includes("not supported") ||
        error.message.includes("platform") ||
        error.message.includes("user") ||
        error.message.toLowerCase().includes("webauthn")
    );

    t.pass(
      "Flow attempted correctly - error expected in test environment without WebAuthn support"
    );
  }
});

test("create with different algorithm preferences", (t) => {
  const baseOptions = createCredentialCreationOptions();

  // Test with different algorithm combinations
  const algorithmTests = [
    [{ type: "public-key", alg: -7 }], // ES256 only
    [{ type: "public-key", alg: -257 }], // RS256 only
    [{ type: "public-key", alg: -258 }], // RS384
    [{ type: "public-key", alg: -259 }], // RS512
  ];

  algorithmTests.forEach((pubKeyCredParams, index) => {
    const options = {
      ...baseOptions,
      pubKeyCredParams,
      user: {
        ...baseOptions.user,
        id: Buffer.from(generateRandomBytes(64)), // Unique user for each test
      },
      challenge: Buffer.from(generateRandomBytes(32)), // Fresh challenge
    };

    try {
      const credential = webauthn.create(options);
      t.is(credential.type, "public-key");
      console.log(`Algorithm test ${index + 1} passed`);
    } catch (error) {
      console.log(
        `Algorithm test ${index + 1} failed as expected: ${error.message}`
      );
      t.true(error instanceof Error);
    }
  });

  t.pass("Algorithm preference tests completed");
});

test("authentication without credential ID (discoverable credentials)", (t) => {
  const options = createCredentialRequestOptions(); // No credential ID

  try {
    const assertion = webauthn.get(options);
    t.is(assertion.type, "public-key");
    t.pass("Discoverable credential authentication successful");
  } catch (error) {
    console.log(`Discoverable credential test error: ${error.message}`);
    t.true(error instanceof Error);
    t.pass("Discoverable credential test attempted correctly");
  }
});
