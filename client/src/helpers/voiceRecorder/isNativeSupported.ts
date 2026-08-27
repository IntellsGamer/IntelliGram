// Standalone, dependency-free feature detection for the WebCodecs-based voice
// recorder. Lives in its own file so that callers (e.g. bootstrapIm) can
// branch on native support WITHOUT pulling the recorder implementation,
// the OGG muxer, or the AudioWorklet source into their bundle.

export default function isNativeVoiceRecorderSupported(): boolean {
  if(
    typeof AudioEncoder === 'undefined' ||
    typeof AudioData === 'undefined' ||
    typeof AudioContext === 'undefined' ||
    !navigator.mediaDevices?.getUserMedia
  ) {
    return false;
  }

  // AudioWorklet is preferred, but WebCodecs can retain the same native
  // OGG/Opus output through ScriptProcessor when module loading is blocked by
  // browser policy or unavailable in an otherwise capable runtime.
  return typeof AudioWorkletNode !== 'undefined' ||
    typeof AudioContext.prototype.createScriptProcessor === 'function';
}
