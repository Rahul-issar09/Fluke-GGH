// One error type for the Community API, from the mock and from a real backend alike.
// code: UNAUTHENTICATED | FORBIDDEN | NOT_FOUND | INVALID | INVALID_IMAGE | SECRET_FOUND | BAD_CREDENTIALS | TAKEN | NETWORK
// SECRET_FOUND carries `hits` (see guard.js) so the UI can show which lines matched.
export class ApiError extends Error {
  constructor(code, message, extra = {}) {
    super(message);
    this.code = code;
    Object.assign(this, extra);
  }
}
