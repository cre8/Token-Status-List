import { JWTPayload } from 'jose';
import { BitsPerStatus } from './status-list';

/**
 * Reference to a status list entry.
 */
export interface StatusListEntry {
  idx: number;
  uri: string;
}

/**
 * Payload for a JWT referecing a status list.
 */
export interface JWTwithStatusListPayload extends JWTPayload {
  status: {
    status_list: StatusListEntry;
  };
}
/**
 * Payload for a JWT with a status list.
 */
export interface StatusListJWTPayload extends JWTPayload {
  status_list: {
    bits: BitsPerStatus;
    lst: string;
  };
}
