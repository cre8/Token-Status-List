import { JWTHeaderParameters, JWTPayload, SignJWT, decodeJwt } from 'jose';
import { StatusList } from './status-list.js';
import {
  JWTwithStatusListPayload,
  StatusListEntry,
  StatusListJWTPayload,
} from './types.js';

/**
 * Create an unsigned JWT with a status list.
 * @param list
 * @param payload
 * @param header
 */
export function createUnsignedJWT(
  list: StatusList,
  payload: JWTPayload,
  header: JWTHeaderParameters
) {
  // validate if the required fieds are present based on https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html#section-5.1

  if (!payload.iss) {
    throw new Error('iss field is required');
  }
  if (!payload.sub) {
    throw new Error('sub field is required');
  }
  if (!payload.iat) {
    throw new Error('iat field is required');
  }
  //exp and tll are optional. We will not validate the business logic of the values like exp > iat etc.

  return new SignJWT({
    ...payload,
    status_list: {
      bits: list.getBitsPerStatus(),
      lst: list.compressStatusList(),
    },
  }).setProtectedHeader({ ...header, typ: 'statuslist+jwt' });
}

/**
 * Get the status list from a JWT, but do not verify the signature.
 * @param jwt
 * @returns
 */
export function getListFromStatusListJWT(jwt: string): StatusList {
  const payload = decodeJwt<StatusListJWTPayload>(jwt);
  const statusList = payload.status_list;
  return StatusList.decompressStatusList(statusList.lst, statusList.bits);
}

/**
 * Get the status list entry from a JWT, but do not verify the signature.
 * @param jwt
 * @returns
 */
export function getStatusListFromJWT(jwt: string): StatusListEntry {
  const payload = decodeJwt<JWTwithStatusListPayload>(jwt);
  return payload.status.status_list;
}
