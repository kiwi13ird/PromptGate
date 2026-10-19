// Open the first nonempty recorded match in its original order. Display order
// never changes the detection result or the enforcement decision.
export function preferredPassageIndex(passages: readonly { input_text: string }[]) {
  const index = passages.findIndex(passage => passage.input_text.trim().length > 0);
  return Math.max(0, index);
}
