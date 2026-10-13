// Compatibility interface; the shared module owns one native fetch observer.
import { installMutationResponseObserver, mutationResponseJson } from './mutation-response-observer.mjs';

export function installDiagnosisResponseObserver(page, origin) {
  return installMutationResponseObserver(page, origin, ['DIAGNOSIS']);
}

export function diagnosisMutationJson(page, response) {
  return mutationResponseJson(page, response, 'DIAGNOSIS');
}
