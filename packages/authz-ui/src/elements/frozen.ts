const freeze = <T>(value: T): T => {
  if (typeof value === 'object' && value !== null) {
    for (const child of Object.values(value)) freeze(child);
    Object.freeze(value);
  }
  return value;
};

/** A deep copy nothing can change. */
export const frozenCopy = <T>(value: T): T => freeze(structuredClone(value));
