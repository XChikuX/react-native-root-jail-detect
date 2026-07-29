/**
 * Category of a {@linkcode DetectionSignal}.
 *
 * Categories group signals by the kind of evidence they represent. They are
 * intended for backend policy filtering and display, not for score computation.
 *
 * @see {@linkcode DetectionSignal.category}
 */
export type SignalCategory =
  | 'filesystem'
  | 'sandbox'
  | 'mount'
  | 'process'
  | 'injection'
  | 'hook'
  | 'property'
  | 'package'
  | 'signature'
  | 'debugger';
