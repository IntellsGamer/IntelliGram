// Native voice recorder built on the standard web platform — no WASM:
//   getUserMedia → AudioContext(48k) → AudioWorklet (PCM tap) →
//     WebCodecs AudioEncoder (opus) → OGG/Opus muxer.
//
// Mirrors the parts of the opus-recorder API that input.ts uses, so the
// caller can swap implementations without conditionals at the use site.

import OggOpusWriter from './oggOpusWriter';
import isNativeVoiceRecorderSupported from './isNativeSupported';
import getStream from '@lib/calls/helpers/getStream';

export {isNativeVoiceRecorderSupported};

const WORKLET_SOURCE = `
class VoiceCaptureProcessor extends AudioWorkletProcessor {
  constructor(options) {
    super();
    const opts = (options && options.processorOptions) || {};
    this.bufferSize = opts.bufferSize || 2048;
    this.buffer = new Float32Array(this.bufferSize);
    this.bufferIndex = 0;
  }
  process(inputs) {
    const input = inputs[0];
    if(!input || !input[0] || input[0].length === 0) return true;
    const channel = input[0];
    let i = 0;
    while(i < channel.length) {
      const remaining = this.bufferSize - this.bufferIndex;
      const toCopy = remaining < (channel.length - i) ? remaining : (channel.length - i);
      this.buffer.set(channel.subarray(i, i + toCopy), this.bufferIndex);
      this.bufferIndex += toCopy;
      i += toCopy;
      if(this.bufferIndex === this.bufferSize) {
        this.port.postMessage(this.buffer.slice(0));
        this.bufferIndex = 0;
      }
    }
    return true;
  }
}
registerProcessor('voice-capture-processor', VoiceCaptureProcessor);
`;

const WORKLET_PROCESSOR_NAME = 'voice-capture-processor';
const WORKLET_BUFFER_SIZE = 2048;
const ENCODER_SAMPLE_RATE = 48000;
const DEFAULT_BITRATE = 32000;
const DEFAULT_FRAME_DURATION_US = 20000;
const DEFAULT_OPUS_FRAME_SAMPLES = (DEFAULT_FRAME_DURATION_US * ENCODER_SAMPLE_RATE) / 1_000_000;
const STARTUP_TIMEOUT_MS = 10_000;
const AUDIO_PIPELINE_TIMEOUT_MS = 2_000;

class RecorderStartupTimeoutError extends Error {
  constructor(stage: string, timeoutMs = STARTUP_TIMEOUT_MS) {
    super(`${stage} did not become ready within ${timeoutMs / 1000} seconds`);
    this.name = 'TimeoutError';
  }
}

// Browser media APIs are permitted to leave requests pending indefinitely (for
// example after a device-driver restart or a stuck worklet module load). Do not
// leave the composer permanently locked in that case. A late media stream is
// immediately stopped, so a timed-out request cannot retain the microphone.
function awaitStartup<T>(
  promise: Promise<T>,
  stage: string,
  disposeLateValue?: (value: T) => void,
  timeoutMs = STARTUP_TIMEOUT_MS
): Promise<T> {
  return new Promise((resolve, reject) => {
    let settled = false;
    const timeout = setTimeout(() => {
      if(settled) return;
      settled = true;
      reject(new RecorderStartupTimeoutError(stage, timeoutMs));
    }, timeoutMs);

    promise.then((value) => {
      if(settled) {
        disposeLateValue?.(value);
        return;
      }
      settled = true;
      clearTimeout(timeout);
      resolve(value);
    }, (error) => {
      if(settled) return;
      settled = true;
      clearTimeout(timeout);
      reject(error);
    });
  });
}

export interface NativeVoiceRecorderConfig {
  encoderSampleRate?: number;
  numberOfChannels?: number;
  encoderBitRate?: number;
  mediaTrackConstraints?: boolean | MediaTrackConstraints;
}

type State = 'inactive' | 'recording' | 'paused';

export default class NativeVoiceRecorder {
  public sourceNode: MediaStreamAudioSourceNode;
  public state: State = 'inactive';

  public onstart: () => void = () => {};
  public onstop: () => void = () => {};
  public onpause: () => void = () => {};
  public onresume: () => void = () => {};
  public ondataavailable: (data: Uint8Array) => void = () => {};

  private config: Required<Pick<NativeVoiceRecorderConfig, 'encoderSampleRate' | 'numberOfChannels' | 'encoderBitRate'>> & {
    mediaTrackConstraints: boolean | MediaTrackConstraints
  };

  private stream: MediaStream;
  private audioContext: AudioContext;
  private workletNode: AudioWorkletNode;
  // WebCodecs itself does not require AudioWorklet. Keep the OGG/Opus encoder
  // path available in browsers where the worklet module cannot start by using
  // the standard ScriptProcessor PCM callback as a compatibility fallback.
  private scriptProcessor: ScriptProcessorNode;
  private encoder: AudioEncoder;
  private writer: OggOpusWriter;
  private encoderTimestampUs = 0;
  private opusHeadCaptured = false;
  public notifySamples: (samples: Float32Array) => void;

  static isSupported = isNativeVoiceRecorderSupported;

  constructor(config: NativeVoiceRecorderConfig = {}) {
    this.config = {
      encoderSampleRate: config.encoderSampleRate ?? ENCODER_SAMPLE_RATE,
      numberOfChannels: config.numberOfChannels ?? 1,
      encoderBitRate: config.encoderBitRate ?? DEFAULT_BITRATE,
      mediaTrackConstraints: config.mediaTrackConstraints ?? true
    };
  }

  // Choose the microphone to record with (empty/undefined = OS default). The
  // caller passes the user's pick from Settings → Speakers and Camera
  // (appSettings.callDevices.microphoneId), same source as calls. Applied on the
  // next start().
  public setMicrophoneId(microphoneId?: string) {
    this.config.mediaTrackConstraints = microphoneId ? {deviceId: {exact: microphoneId}} : true;
  }

  public async start(): Promise<void> {
    if(this.state !== 'inactive') return;

    // stop()/failed-start cleanup leaves no live audio graph. Clear stale node
    // references before choosing this session's preferred pipeline so a prior
    // fallback can never suppress a fresh fallback decision.
    this.workletNode = undefined;
    this.scriptProcessor = undefined;

    try {
      // Reuse the call stack's getUserMedia chokepoint: if the selected mic is
      // gone it strips the deviceId, clears the stale appSettings.callDevices
      // microphoneId, and retries on the OS default. The explicit bound also
      // guarantees a hung capture request restores the composer instead of
      // leaving `isStartingRecording` true forever.
      this.stream = await awaitStartup(
        getStream({audio: this.config.mediaTrackConstraints}),
        'Microphone request',
        (stream) => stream.getTracks().forEach((track) => track.stop())
      );

      this.audioContext = new AudioContext({sampleRate: this.config.encoderSampleRate});
      this.sourceNode = this.audioContext.createMediaStreamSource(this.stream);

      const canUseWorklet = typeof AudioWorkletNode !== 'undefined' && !!this.audioContext.audioWorklet;
      if(canUseWorklet) {
        const blob = new Blob([WORKLET_SOURCE], {type: 'application/javascript'});
        const workletUrl = URL.createObjectURL(blob);
        try {
          await awaitStartup(
            this.audioContext.audioWorklet.addModule(workletUrl),
            'AudioWorklet module',
            undefined,
            AUDIO_PIPELINE_TIMEOUT_MS
          );
          this.workletNode = new AudioWorkletNode(this.audioContext, WORKLET_PROCESSOR_NAME, {
            numberOfInputs: 1,
            numberOfOutputs: 1,
            outputChannelCount: [this.config.numberOfChannels],
            processorOptions: {bufferSize: WORKLET_BUFFER_SIZE}
          });
          this.workletNode.port.onmessage = (e: MessageEvent<Float32Array>) => this.onPcmSamples(e.data);
          this.sourceNode.connect(this.workletNode);
          // AudioWorkletNode needs a downstream consumer for process() to be
          // called; its output is silent because the processor never writes it.
          this.workletNode.connect(this.audioContext.destination);
        } catch(error) {
          // A Blob-backed worklet can be rejected or remain stuck by a browser
          // policy even though capture and WebCodecs work. Fall through to the
          // synchronous ScriptProcessor PCM tap instead of leaving recording
          // unavailable after microphone permission has been granted.
          try {
            this.workletNode?.disconnect();
          } catch(e) {}
          if(this.workletNode) this.workletNode.port.onmessage = null;
          this.workletNode = undefined;
          console.warn('[NativeVoiceRecorder] AudioWorklet unavailable; using ScriptProcessor fallback:', error);
        } finally {
          URL.revokeObjectURL(workletUrl);
        }
      }

      if(!this.workletNode) {
        // Older or policy-restricted Chromium builds can expose WebCodecs while
        // worklet module startup is unavailable. ScriptProcessor remains enough
        // to feed the same PCM → WebCodecs → OGG/Opus pipeline.
        this.scriptProcessor = this.audioContext.createScriptProcessor(
          WORKLET_BUFFER_SIZE,
          this.config.numberOfChannels,
          this.config.numberOfChannels
        );
        this.scriptProcessor.onaudioprocess = (event) => {
          const samples = event.inputBuffer.getChannelData(0).slice();
          this.onPcmSamples(samples);
          for(let channel = 0; channel < event.outputBuffer.numberOfChannels; channel++) {
            event.outputBuffer.getChannelData(channel).fill(0);
          }
        };
        this.sourceNode.connect(this.scriptProcessor);
        this.scriptProcessor.connect(this.audioContext.destination);
      }

      this.writer = new OggOpusWriter({
        channels: this.config.numberOfChannels,
        inputSampleRate: this.config.encoderSampleRate
      });

      this.encoder = new AudioEncoder({
        output: (chunk, metadata) => this.onEncoderChunk(chunk, metadata),
        error: (err) => console.error('[NativeVoiceRecorder] encoder error:', err)
      });

      this.encoder.configure({
        codec: 'opus',
        sampleRate: this.config.encoderSampleRate,
        numberOfChannels: this.config.numberOfChannels,
        bitrate: this.config.encoderBitRate
      });

      // The recorder is reached after Web K's async chat-rights/profile checks,
      // so the AudioContext may no longer inherit the original click gesture.
      // Resume explicitly and bound it for the same no-hang guarantee.
      if(this.audioContext.state === 'suspended') {
        await awaitStartup(this.audioContext.resume(), 'Audio context', undefined, AUDIO_PIPELINE_TIMEOUT_MS);
      }

      this.state = 'recording';
      this.encoderTimestampUs = 0;
      this.opusHeadCaptured = false;
      this.onstart();
    } catch(error) {
      await this.cleanupFailedStart();
      throw error;
    }
  }

  private async cleanupFailedStart() {
    try {
      this.sourceNode?.disconnect();
    } catch(e) {}
    try {
      this.workletNode?.disconnect();
    } catch(e) {}
    if(this.workletNode) this.workletNode.port.onmessage = null;
    this.workletNode = undefined;
    if(this.scriptProcessor) {
      try {
        this.scriptProcessor.disconnect();
      } catch(e) {}
      this.scriptProcessor.onaudioprocess = null;
    }
    this.scriptProcessor = undefined;
    if(this.stream) this.stream.getTracks().forEach((track) => track.stop());
    if(this.encoder && this.encoder.state !== 'closed') {
      try {
        this.encoder.close();
      } catch(e) {}
    }
    if(this.audioContext && this.audioContext.state !== 'closed') {
      try {
        await this.audioContext.close();
      } catch(e) {}
    }
  }

  private onPcmSamples(samples: Float32Array) {
    if(this.state !== 'recording') return;
    if(this.notifySamples) this.notifySamples(samples);
    const numberOfFrames = samples.length / this.config.numberOfChannels;
    const audioData = new AudioData({
      format: 'f32-planar',
      sampleRate: this.config.encoderSampleRate,
      numberOfFrames,
      numberOfChannels: this.config.numberOfChannels,
      timestamp: this.encoderTimestampUs,
      data: samples.slice()
    });
    this.encoderTimestampUs += (numberOfFrames * 1_000_000) / this.config.encoderSampleRate;
    try {
      this.encoder.encode(audioData);
    } catch(err) {
      console.error('[NativeVoiceRecorder] encode error:', err);
    }
    audioData.close();
  }

  private onEncoderChunk(chunk: EncodedAudioChunk, metadata?: EncodedAudioChunkMetadata) {
    if(!this.opusHeadCaptured && metadata?.decoderConfig?.description) {
      const desc = metadata.decoderConfig.description;
      let bytes: Uint8Array;
      if(desc instanceof ArrayBuffer) {
        bytes = new Uint8Array(desc);
      } else {
        const view = desc as ArrayBufferView;
        bytes = new Uint8Array(view.buffer as ArrayBuffer, view.byteOffset, view.byteLength);
      }
      this.writer.setOpusHead(bytes);
      this.opusHeadCaptured = true;
    }

    const data = new Uint8Array(chunk.byteLength);
    chunk.copyTo(data);

    const durationUs = chunk.duration ?? DEFAULT_FRAME_DURATION_US;
    const durationSamples = Math.round((durationUs * ENCODER_SAMPLE_RATE) / 1_000_000) || DEFAULT_OPUS_FRAME_SAMPLES;
    this.writer.writePacket(data, durationSamples);
  }

  // Pause keeps the worklet → encoder pipeline wired up but ignores incoming
  // PCM samples. The encoder is flushed so the OGG snapshot is playable.
  public async pause(): Promise<void> {
    if(this.state !== 'recording') return;
    this.state = 'paused';
    if(this.encoder && this.encoder.state !== 'closed') {
      try {
        await this.encoder.flush();
      } catch(e) {}
    }
    this.onpause();
  }

  public resume(): void {
    if(this.state !== 'paused') return;
    this.state = 'recording';
    this.onresume();
  }

  // Build a playable OGG of everything captured so far without ending the
  // recording. Used to preview the in-progress voice message during pause.
  public getSnapshot(): Uint8Array {
    return this.writer ? this.writer.snapshot() : new Uint8Array(0);
  }

  public async stop(): Promise<void> {
    if(this.state === 'inactive') return;
    this.state = 'inactive';

    try {
      this.sourceNode?.disconnect();
    } catch(e) {}
    if(this.workletNode) {
      try {
        this.workletNode.disconnect();
      } catch(e) {}
      this.workletNode.port.onmessage = null;
    }
    this.workletNode = undefined;
    if(this.scriptProcessor) {
      try {
        this.scriptProcessor.disconnect();
      } catch(e) {}
      this.scriptProcessor.onaudioprocess = null;
    }
    this.scriptProcessor = undefined;

    if(this.stream) {
      this.stream.getTracks().forEach((t) => t.stop());
    }

    if(this.encoder && this.encoder.state !== 'closed') {
      try {
        await this.encoder.flush();
      } catch(e) {
        console.error('[NativeVoiceRecorder] flush error:', e);
      }
      try {
        this.encoder.close();
      } catch(e) {}
    }

    const ogg = this.writer ? this.writer.finalize() : new Uint8Array(0);

    if(this.audioContext && this.audioContext.state !== 'closed') {
      try {
        await this.audioContext.close();
      } catch(e) {}
    }

    this.ondataavailable(ogg);
    this.onstop();
  }
}
