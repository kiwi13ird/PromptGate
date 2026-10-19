export async function applyWithRollback({ capture, applyNext, commit, rollback, failSafe }) {
  const previous = await capture();
  try {
    const result = await applyNext();
    await commit(result);
    return result;
  } catch (applyError) {
    try {
      await rollback(previous);
    } catch (rollbackError) {
      await failSafe?.(applyError, rollbackError);
      const error = new Error("보호를 켜지 못했습니다. 보안 관리자에게 문의해 주세요.");
      error.code = "ROLLBACK_FAILED";
      error.technicalDetail = `${applyError?.message || applyError}; rollback: ${rollbackError?.message || rollbackError}`;
      throw error;
    }
    throw applyError;
  }
}

export async function enforceIdentityFailSafe({ desiredProtection, proxyState, removeIdentity, markConflict }) {
  const ownsPac = proxyState?.levelOfControl === "controlled_by_this_extension" && proxyState?.mode === "pac_script";
  if (!desiredProtection || ownsPac) return false;
  await removeIdentity();
  await markConflict();
  return true;
}

export function createBootstrapOnce(task) {
  let promise;
  return () => promise ??= Promise.resolve().then(task).catch((error) => { promise = undefined; throw error; });
}

export function createSerialExecutor() {
  let tail = Promise.resolve();
  return (work) => { tail = tail.then(work, work); return tail; };
}
