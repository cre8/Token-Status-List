// statuslist-jwt.spec.ts
import {
  JWTwithStatusListPayload,
  createUnsignedJWT,
  getListFromStatusListJWT,
  getStatusListFromJWT,
} from './status-list-jwt';
import { StatusList } from './status-list';
import {
  JWTPayload,
  JWTHeaderParameters,
  jwtVerify,
  KeyLike,
  SignJWT,
} from 'jose';
import { beforeAll, describe, expect, it } from 'vitest';
import { generateKeyPairSync } from 'node:crypto';

describe('createUnsignedJWT', () => {
  let publicKey: KeyLike;
  let privateKey: KeyLike;

  beforeAll(() => {
    // Generate a key pair for testing
    const keyPair = generateKeyPairSync('ec', {
      namedCurve: 'P-256',
    });
    publicKey = keyPair.publicKey;
    privateKey = keyPair.privateKey;
  });

  it('should create an unsigned JWT with a status list', async () => {
    const list = new StatusList([1, 0, 1, 1, 1], 1);
    const iss = 'https://example.com';
    const payload: JWTPayload = {
      iss,
      sub: `${iss}/statuslist/1`,
      iat: new Date().getTime() / 1000,
    };
    const header: JWTHeaderParameters = { alg: 'ES256' };

    const jwt = createUnsignedJWT(list, payload, header);

    // Sign the JWT with the private key
    const signedJwt = await jwt.sign(privateKey);
    // Verify the signed JWT with the public key
    const verified = await jwtVerify(signedJwt, publicKey);
    expect(verified.payload.status_list).toEqual({
      bits: list.getBitsPerStatus(),
      lst: list.compressStatusList(),
    });
    expect(verified.protectedHeader.typ).toBe('statuslist+jwt');
  });

  it('should get the status list from a JWT without verifying the signature', async () => {
    const list = [1, 0, 1, 0, 1];
    const statusList = new StatusList(list, 1);
    const iss = 'https://example.com';
    const payload: JWTPayload = {
      iss,
      sub: `${iss}/statuslist/1`,
      iat: new Date().getTime() / 1000,
    };
    const header: JWTHeaderParameters = { alg: 'ES256' };

    const jwt = await createUnsignedJWT(statusList, payload, header).sign(
      privateKey
    );
    const extractedList = getListFromStatusListJWT(jwt);
    for (let i = 0; i < list.length; i++) {
      expect(extractedList.getStatus(i)).toBe(list[i]);
    }
  });

  it('should throw an error if the JWT is invalid', async () => {
    const list = [1, 0, 1, 0, 1];
    const statusList = new StatusList(list, 2);
    const iss = 'https://example.com';
    const header: JWTHeaderParameters = { alg: 'ES256' };
    let payload: JWTPayload = {
      sub: `${iss}/statuslist/1`,
      iat: new Date().getTime() / 1000,
    };
    expect(() => {
      createUnsignedJWT(statusList, payload, header).sign(privateKey);
    }).toThrow('iss field is required');

    payload = {
      iss,
      iat: new Date().getTime() / 1000,
    };
    expect(() => {
      createUnsignedJWT(statusList, payload, header).sign(privateKey);
    }).toThrow('sub field is required');

    payload = {
      iss,
      sub: `${iss}/statuslist/1`,
    };
    expect(() => {
      createUnsignedJWT(statusList, payload, header).sign(privateKey);
    }).toThrow('iat field is required');
  });

  it('should get the status entry from a JWT', async () => {
    const payload: JWTwithStatusListPayload = {
      status: {
        status_list: {
          idx: 0,
          uri: 'https://example.com/status/1',
        },
      },
    };
    const jwt = await new SignJWT(payload)
      .setProtectedHeader({ alg: 'ES256' })
      .sign(privateKey);
    const reference = getStatusListFromJWT(jwt);
    expect(reference).toEqual(payload.status.status_list);
  });
});
