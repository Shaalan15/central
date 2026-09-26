// Copyright (C) 2026 The Central Authors.
// SPDX-License-Identifier: AGPL-3.0-only

// WebAuthn helpers: Central sends options as JSON with base64url-encoded binary fields
// (go-webauthn format) and expects credentials back in the same encoding.

function fromB64url(s: string): ArrayBuffer {
  const b64 = s
    .replace(/-/g, '+')
    .replace(/_/g, '/')
    .padEnd(Math.ceil(s.length / 4) * 4, '=');
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out.buffer;
}

function toB64url(buf: ArrayBuffer | null | undefined): string | undefined {
  if (!buf) return undefined;
  const bytes = new Uint8Array(buf);
  let bin = '';
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

type Json = Record<string, unknown>;

function unwrap(json: string): Json {
  const o = JSON.parse(json) as Json;
  return (o['publicKey'] as Json | undefined) ?? o;
}

function decodeDescriptors(list: unknown): PublicKeyCredentialDescriptor[] | undefined {
  if (!Array.isArray(list)) return undefined;
  return (list as Json[]).map((d) => ({
    ...(d as object),
    id: fromB64url(d['id'] as string),
  })) as PublicKeyCredentialDescriptor[];
}

/** Reports whether passkeys can be used in this browser. */
export function passkeysSupported(): boolean {
  return typeof window !== 'undefined' && !!window.PublicKeyCredential && !!navigator.credentials;
}

/** Runs navigator.credentials.get and returns the assertion JSON for Central. */
export async function getAssertion(optionsJson: string): Promise<string> {
  const o = unwrap(optionsJson);
  const publicKey: PublicKeyCredentialRequestOptions = {
    ...(o as object),
    challenge: fromB64url(o['challenge'] as string),
    allowCredentials: decodeDescriptors(o['allowCredentials']),
  } as PublicKeyCredentialRequestOptions;
  const cred = (await navigator.credentials.get({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error('No passkey was selected.');
  const r = cred.response as AuthenticatorAssertionResponse;
  return JSON.stringify({
    id: cred.id,
    rawId: toB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: toB64url(r.clientDataJSON),
      authenticatorData: toB64url(r.authenticatorData),
      signature: toB64url(r.signature),
      userHandle: toB64url(r.userHandle),
    },
  });
}

/** Runs navigator.credentials.create and returns the attestation JSON for Central. */
export async function createCredential(optionsJson: string): Promise<string> {
  const o = unwrap(optionsJson);
  const user = o['user'] as Json;
  const publicKey = {
    ...(o as object),
    challenge: fromB64url(o['challenge'] as string),
    user: { ...(user as object), id: fromB64url(user['id'] as string) },
    excludeCredentials: decodeDescriptors(o['excludeCredentials']),
  } as PublicKeyCredentialCreationOptions;
  const cred = (await navigator.credentials.create({ publicKey })) as PublicKeyCredential | null;
  if (!cred) throw new Error('The passkey was not created.');
  const r = cred.response as AuthenticatorAttestationResponse;
  return JSON.stringify({
    id: cred.id,
    rawId: toB64url(cred.rawId),
    type: cred.type,
    authenticatorAttachment: cred.authenticatorAttachment ?? undefined,
    clientExtensionResults: cred.getClientExtensionResults(),
    response: {
      clientDataJSON: toB64url(r.clientDataJSON),
      attestationObject: toB64url(r.attestationObject),
      transports: typeof r.getTransports === 'function' ? r.getTransports() : undefined,
    },
  });
}
