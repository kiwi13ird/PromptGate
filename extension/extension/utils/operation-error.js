export function operationError(code, userMessage, technicalDetail = "") {
  const error = new Error(userMessage);
  error.code = code;
  error.userMessage = userMessage;
  error.technicalDetail = String(technicalDetail || "").slice(0, 500);
  return error;
}

export function publicError(error) {
  return {
    ok: false,
    errorCode: error?.code || "OPERATION_FAILED",
    errorMessage: error?.userMessage || "요청을 처리하지 못했습니다. 잠시 후 다시 시도하고, 계속되면 보안 관리자에게 문의해 주세요.",
    technicalDetail: String(error?.technicalDetail || error?.message || error || "").slice(0, 500),
    timestamp: new Date().toISOString()
  };
}
