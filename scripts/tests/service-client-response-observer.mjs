// Compatibility interface; the shared module owns one native fetch observer.
import { installMutationResponseObserver, mutationResponseJson } from './mutation-response-observer.mjs';

export function installServiceClientResponseObserver(page, origin) {
  return installMutationResponseObserver(page, origin, ['SERVICE_CLIENT']);
}

export function serviceClientMutationJson(page, response) {
  return mutationResponseJson(page, response, 'SERVICE_CLIENT');
}
