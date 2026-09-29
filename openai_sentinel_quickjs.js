'use strict';

const fs = require('node:fs');
const vm = require('node:vm');
const cryptoMod = require('node:crypto');
const zlibMod = require('node:zlib');

const input = JSON.parse(fs.readFileSync(0, 'utf8'));
const sdkRaw = fs.readFileSync(process.env.OPENAI_SENTINEL_SDK_FILE, 'utf8');

const EXPOSE_PATCH = "return o?r?.[n(63)]?ce({so:o,c:r[n(63)]},t):o:null},t.token=ye,t}({});";
const EXPOSE_REPLACEMENT =
  "return o?r?.[n(63)]?ce({so:o,c:r[n(63)]},t):o:null},t.token=ye,t.__debug_n=_n,t.__debug_bindProof=D,t}({});";
const INSTANCE_PATCH = "var P=new _;";
const INSTANCE_REPLACEMENT = "var P=new _;globalThis.__debugP=P;";
const SDK_GLOBAL_PATCH = "var SentinelSDK=";
const SDK_GLOBAL_REPLACEMENT = "globalThis.SentinelSDK=";

let sdk = sdkRaw;
sdk = sdk.replace(SDK_GLOBAL_PATCH, SDK_GLOBAL_REPLACEMENT);
sdk = sdk.replace(INSTANCE_PATCH, INSTANCE_REPLACEMENT);
sdk = sdk.replace(EXPOSE_PATCH, EXPOSE_REPLACEMENT);

// ─── Helpers ───────────────────────────────────────────────────

function createStorage() {
  const map = new Map();
  return {
    get length() { return map.size; },
    clear() { map.clear(); },
    getItem(key) { return map.has(String(key)) ? map.get(String(key)) : null; },
    setItem(key, value) { map.set(String(key), String(value)); },
    removeItem(key) { map.delete(String(key)); },
    key(index) { return [...map.keys()][index] || null; },
  };
}

function genericElement(tagName) {
  const tag = String(tagName || 'div').toLowerCase();
  return {
    nodeType: 1,
    tagName: tag.toUpperCase(),
    nodeName: tag.toUpperCase(),
    style: {},
    children: [],
    childNodes: [],
    src: '',
    id: '',
    className: '',
    innerHTML: '',
    textContent: '',
    parentNode: null,
    appendChild(child) { this.children.push(child); child.parentNode = this; return child; },
    removeChild(child) { this.children = this.children.filter(x => x !== child); return child; },
    insertBefore(n) { this.children.push(n); return n; },
    setAttribute() {},
    getAttribute() { return null; },
    hasAttribute() { return false; },
    removeAttribute() {},
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent() { return true; },
    cloneNode() { return genericElement(tagName); },
    contains() { return false; },
    getBoundingClientRect() {
      return { x: 0, y: 0, width: 0, height: 0, top: 0, left: 0, right: 0, bottom: 0 };
    },
    focus() {},
    blur() {},
    click() {},
  };
}

function canvasElement() {
  const el = genericElement('canvas');
  el.width = 300;
  el.height = 150;
  const pngBytes = buildPng(
    8,
    8,
    Buffer.from(Array.from({ length: 8 * 8 * 4 }, () => Math.floor(deviceRng() * 256))),
  );
  el.toDataURL = () => 'data:image/png;base64,' + pngBytes.toString('base64');
  el.toBlob = (cb) => { if (cb) cb(new Uint8Array(pngBytes)); };
  el.getContext = (kind) => {
    if (kind === '2d') {
      return {
        fillRect() {}, clearRect() {}, strokeRect() {},
        getImageData(x, y, w, h) {
          const width = Number(w) > 0 ? Number(w) : 300;
          const height = Number(h) > 0 ? Number(h) : 150;
          // 真机对同一画布同一区域读两次必须逐字节一致；此前这里是"每调用
          // 再随机一次"，探测器读两次即识破。改为按 (device, canvas, rect)
          // 确定性的像素流，同区域永远同值，不同区域才分化。
          const pxSeed = hashSeed(
            String(input.device_id || '')
            + ':gi:' + (el.width || 300) + 'x' + (el.height || 150)
            + ':' + (Number(x) || 0) + ',' + (Number(y) || 0)
            + ':' + width + 'x' + height,
          );
          const pxRng = mulberry32(pxSeed);
          const data = new Uint8Array(width * height * 4);
          for (let i = 0; i < data.length; i++) data[i] = Math.floor(pxRng() * 256);
          return { data, width, height, colorSpace: 'srgb' };
        },
        putImageData() {}, createImageData() { return { data: new Uint8Array(0) }; },
        setTransform() {}, resetTransform() {}, drawImage() {},
        save() {}, restore() {}, beginPath() {}, closePath() {},
        moveTo() {}, lineTo() {}, clip() {}, quadraticCurveTo() {},
        bezierCurveTo() {}, arc() {}, arcTo() {}, rect() {},
        fill() {}, stroke() {},
        measureText(t) {
          const s = String(t || '');
          // 真机宽度 = 每字符固定推进 + 亚像素级个体差，且同一字符串两次
          // 测量必须同值。此前按字符逐个叠加随机数，噪声随长度线性放大，
          // 且两次测量因随机流前进而不同。改为：字符数 × 固定 em 宽 + 按
          // (device, 字符串) 哈希的一次有界偏移（±0.6px），长度无关。
          const offRng = mulberry32(hashSeed(String(input.device_id || '') + ':mt:' + s));
          const width = s.length * 7.2 + (offRng() * 1.2 - 0.6);
          return { width: Math.max(0, Number(width.toFixed(4))) };
        },
        fillText() {}, strokeText() {},
        scale() {}, rotate() {}, translate() {},
        createLinearGradient() { return { addColorStop() {} }; },
        createRadialGradient() { return { addColorStop() {} }; },
        canvas: el,
        fillStyle: '', strokeStyle: '', lineWidth: 1, font: '10px sans-serif',
        textAlign: 'start', textBaseline: 'alphabetic',
        globalAlpha: 1, globalCompositeOperation: 'source-over',
      };
    }
    if (!['webgl', 'experimental-webgl', 'webgl2'].includes(kind)) return null;
    const dbg = { UNMASKED_VENDOR_WEBGL: 0x9245, UNMASKED_RENDERER_WEBGL: 0x9246 };
    const prof = gpuProfile();
    const C = {
      VERSION: 0x1F02,
      SHADING_LANGUAGE_VERSION: 0x8B8C,
      VENDOR: 0x1F00,
      RENDERER: 0x1F01,
      MAX_TEXTURE_SIZE: 0x0D33,
      MAX_VIEWPORT_DIMS: 0x0D3A,
      MAX_VERTEX_ATTRIBS: 0x8869,
      MAX_TEXTURE_IMAGE_UNITS: 0x8872,
      MAX_COMBINED_TEXTURE_IMAGE_UNITS: 0x8B4D,
      ALIASED_LINE_WIDTH_RANGE: 0x846E,
      ALIASED_POINT_SIZE_RANGE: 0x846D,
      MAX_RENDERBUFFER_SIZE: 0x84E8,
    };
    return {
      VENDOR: 0x1F00, RENDERER: 0x1F01,
      getExtension(name) { return name === 'WEBGL_debug_renderer_info' ? dbg : null; },
      getParameter(p) {
        if (p === dbg.UNMASKED_VENDOR_WEBGL || p === 0x1F00) return gpuVendor;
        if (p === dbg.UNMASKED_RENDERER_WEBGL || p === 0x1F01) return gpuRenderer;
        if (p === C.VERSION) return prof.glVersion;
        if (p === C.SHADING_LANGUAGE_VERSION) return prof.glslVersion;
        if (p === C.VENDOR) return prof.glVendor;
        if (p === C.MAX_TEXTURE_SIZE || p === C.MAX_RENDERBUFFER_SIZE) return prof.maxTextureSize;
        if (p === C.MAX_VIEWPORT_DIMS) return new Int32Array(prof.maxViewportDims);
        if (p === C.MAX_VERTEX_ATTRIBS) return prof.maxVertexAttribs;
        if (p === C.MAX_TEXTURE_IMAGE_UNITS || p === C.MAX_COMBINED_TEXTURE_IMAGE_UNITS) return prof.maxTextureUnits;
        if (p === C.ALIASED_LINE_WIDTH_RANGE) return new Float32Array([1, 1]);
        if (p === C.ALIASED_POINT_SIZE_RANGE) return new Float32Array([1, 1024]);
        return 0;
      },
      getSupportedExtensions() { return WEBGL_EXTENSIONS.slice(); },
      getShaderPrecisionFormat() {
        return { rangeMin: 127, rangeMax: 127, precision: 23 };
      },
      createBuffer() { return {}; }, createTexture() { return {}; },
      createShader() { return {}; }, createProgram() { return {}; },
      bindBuffer() {}, bufferData() {}, bindTexture() {},
      viewport() {}, clear() {}, enable() {}, disable() {},
      drawArrays() {}, drawElements() {},
      getContextAttributes() {
        return {
          alpha: true, antialias: true, depth: true, desynchronized: false,
          failIfMajorPerformanceCaveat: false, powerPreference: 'default',
          premultipliedAlpha: true, preserveDrawingBuffer: false, stencil: false,
        };
      },
      canvas: el,
    };
  };
  return el;
}

// ─── Event listener infrastructure (shared between main & VM) ─

const _listeners = new Map();

function addListener(type, callback) {
  if (typeof callback !== 'function') return;
  const bucket = _listeners.get(type) || [];
  bucket.push(callback);
  _listeners.set(type, bucket);
}

function removeListener(type, callback) {
  const bucket = _listeners.get(type) || [];
  _listeners.set(type, bucket.filter(fn => fn !== callback));
}

async function dispatch(type, init) {
  const event = {
    type,
    bubbles: true,
    cancelable: true,
    defaultPrevented: false,
    timeStamp: performance.now(),
    target: null,
    currentTarget: null,
    preventDefault() { this.defaultPrevented = true; },
    stopPropagation() {},
    stopImmediatePropagation() {},
    ...(init || {}),
  };
  for (const cb of [...(_listeners.get(type) || [])]) {
    try { await cb(event); } catch (_) {}
  }
}

// ─── iframe mock ───────────────────────────────────────────────

let iframeObject = null;
let capturedProof = null;

// ─── Build the VM context ──────────────────────────────────────

const screenW = Number(input.screen_width || 1920);
const screenH = Number(input.screen_height || 1080);
const gpuVendor = String(input.gpu_vendor || 'Google Inc. (Intel)');
const gpuRenderer =
  String(input.gpu_renderer || 'ANGLE (Intel, Intel(R) UHD Graphics Direct3D11 vs_5_0 ps_5_0, D3D11)');
const scripts = [];

// ─── 每号确定性随机源（canvas/audio/扩展细节按 device_id 派生）───────────
function hashSeed(str) {
  let h = 2166136261 >>> 0;
  const s = String(str || '');
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i);
    h = Math.imul(h, 16777619) >>> 0;
  }
  return h >>> 0;
}
function mulberry32(seed) {
  let a = seed >>> 0;
  return function () {
    a |= 0;
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}
const deviceRng = mulberry32(hashSeed(String(input.device_id || '')));

// ─── 最小 PNG 编码器（canvas.toDataURL 用），让每号的 canvas 指纹可区分 ──
const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n++) {
    let c = n;
    for (let k = 0; k < 8; k++) c = c & 1 ? 0xEDB88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();
function crc32(buf) {
  let c = 0xFFFFFFFF;
  for (let i = 0; i < buf.length; i++) c = CRC_TABLE[(c ^ buf[i]) & 0xFF] ^ (c >>> 8);
  return (c ^ 0xFFFFFFFF) >>> 0;
}
function pngChunk(type, data) {
  const out = Buffer.alloc(12 + data.length);
  out.writeUInt32BE(data.length, 0);
  out.write(type, 4, 'ascii');
  data.copy(out, 8);
  out.writeUInt32BE(crc32(out.subarray(4, 8 + data.length)), 8 + data.length);
  return out;
}
function buildPng(width, height, rgba) {
  const ihdr = Buffer.alloc(13);
  ihdr.writeUInt32BE(width, 0);
  ihdr.writeUInt32BE(height, 4);
  ihdr[8] = 8; ihdr[9] = 6; ihdr[10] = 0; ihdr[11] = 0; ihdr[12] = 0;
  const raw = Buffer.alloc((width * 4 + 1) * height);
  for (let y = 0; y < height; y++) {
    raw[y * (width * 4 + 1)] = 0;
    rgba.copy(raw, y * (width * 4 + 1) + 1, y * width * 4, (y + 1) * width * 4);
  }
  const idat = zlibMod.deflateSync(raw);
  return Buffer.concat([
    Buffer.from([0x89, 0x50, 0x4E, 0x47, 0x0D, 0x0A, 0x1A, 0x0A]),
    pngChunk('IHDR', ihdr),
    pngChunk('IDAT', idat),
    pngChunk('IEND', Buffer.alloc(0)),
  ]);
}

// ─── WebGL 参数画像（按显卡家族），参数值取真机常见量级 ───────────────────
const WEBGL_EXTENSIONS = [
  'ANGLE_instanced_arrays', 'EXT_blend_minmax', 'EXT_color_buffer_half_float',
  'EXT_disjoint_timer_query', 'EXT_float_blend', 'EXT_frag_depth',
  'EXT_shader_texture_lod', 'EXT_texture_compression_rgtc',
  'EXT_texture_filter_anisotropic', 'EXT_sRGB', 'OES_element_index_uint',
  'OES_fbo_render_mipmap', 'OES_standard_derivatives', 'OES_texture_float',
  'OES_texture_float_linear', 'OES_texture_half_float',
  'OES_texture_half_float_linear', 'OES_vertex_array_object',
  'WEBGL_color_buffer_float', 'WEBGL_compressed_texture_s3tc',
  'WEBGL_compressed_texture_s3tc_srgb', 'WEBGL_debug_renderer_info',
  'WEBGL_debug_shaders', 'WEBGL_depth_texture', 'WEBGL_draw_buffers',
  'WEBGL_lose_context', 'WEBGL_multi_draw', 'WEBGL_polygon_mode',
];
const GPU_PROFILES = {
  nvidia: {
    glVersion: 'WebGL 2.0 (OpenGL ES 3.0 Chromium)',
    glVendor: 'WebKit',
    glslVersion: 'WebGL GLSL ES 3.00 (OpenGL ES GLSL ES 3.0 Chromium)',
    maxTextureSize: 16384,
    maxViewportDims: [32768, 32768],
    maxVertexAttribs: 16,
    maxTextureUnits: 32,
  },
  amd: {
    glVersion: 'WebGL 2.0 (OpenGL ES 3.0 Chromium)',
    glVendor: 'WebKit',
    glslVersion: 'WebGL GLSL ES 3.00 (OpenGL ES GLSL ES 3.0 Chromium)',
    maxTextureSize: 16384,
    maxViewportDims: [16384, 16384],
    maxVertexAttribs: 16,
    maxTextureUnits: 32,
  },
  intel: {
    glVersion: 'WebGL 2.0 (OpenGL ES 3.0 Chromium)',
    glVendor: 'WebKit',
    glslVersion: 'WebGL GLSL ES 3.00 (OpenGL ES GLSL ES 3.0 Chromium)',
    maxTextureSize: 16384,
    maxViewportDims: [16384, 16384],
    maxVertexAttribs: 16,
    maxTextureUnits: 32,
  },
};
function gpuProfile() {
  const r = String(gpuRenderer || '').toLowerCase();
  if (r.includes('nvidia')) return GPU_PROFILES.nvidia;
  if (r.includes('amd') || r.includes('radeon')) return GPU_PROFILES.amd;
  return GPU_PROFILES.intel;
}

// ─── AudioContext 最小实现：每号确定性的采样数据，避免整批同值 ────────────
function makeAudioBuffer(length) {
  const data = new Float32Array(length);
  // 短 buffer 是探测器常用的"静音探针"（如 OfflineAudioContext(1,100,44100)），
  // 真机输出必须为 0；长 buffer 才按 (device, length) 确定性填充微幅噪声，
  // 保证同一账号两次渲染同值，且整批账号不共享同一音频指纹。
  if (length > 256) {
    const audioRng = mulberry32(hashSeed(String(input.device_id || '') + ':audio:' + length));
    for (let i = 0; i < length; i++) data[i] = (audioRng() * 2 - 1) * 0.0008;
  }
  return {
    length,
    duration: length / 44100,
    sampleRate: 44100,
    numberOfChannels: 1,
    copyFromChannel() {},
    copyToChannel() {},
    getChannelData() { return data; },
  };
}
function makeOscillatorNode() {
  return {
    type: 'sine',
    frequency: { value: 440, setValueAtTime() {}, linearRampToValueAtTime() {}, exponentialRampToValueAtTime() {} },
    detune: { value: 0, setValueAtTime() {} },
    connect() {}, disconnect() {}, start() {}, stop() {},
  };
}
function makeAudioContext() {
  return {
    destination: {},
    currentTime: 0,
    sampleRate: 44100,
    state: 'running',
    baseLatency: 0.01,
    createOscillator: makeOscillatorNode,
    createGain() { return { gain: { value: 1, setValueAtTime() {} }, connect() {}, disconnect() {} }; },
    createDynamicsCompressor() { return { threshold: { value: -24 }, connect() {}, disconnect() {} }; },
    createAnalyser() { return { fftSize: 2048, frequencyBinCount: 1024, connect() {}, disconnect() {} }; },
    createBufferSource() { return { buffer: null, connect() {}, start() {}, stop() {} }; },
    decodeAudioData: async () => makeAudioBuffer(44100),
    resume: async () => {},
    suspend: async () => {},
    close: async () => {},
  };
}

const documentElement = genericElement('html');
documentElement.clientWidth = screenW;
documentElement.clientHeight = screenH;
documentElement.scrollWidth = screenW;
documentElement.scrollHeight = screenH;

const bodyEl = genericElement('body');
bodyEl.appendChild = function (child) {
  this.children.push(child);
  child.parentNode = this;
  if (child === iframeObject) {
    setTimeout(() => {
      for (const cb of (iframeObject._load || [])) {
        try { cb(); } catch (_) {}
      }
    }, 1);
  }
  return child;
};

const navPlatform = input.platform != null ? String(input.platform) : 'Win32';
const navVendor = input.vendor != null ? String(input.vendor) : 'Google Inc.';
const browserType = String(input.browser_type || '');
const isChromeFamily = browserType === 'chrome';

// 真 Chrome 的 navigator.plugins / mimeTypes 有具体条目；Firefox/Safari 已
// 移除 NPAPI 插件，length 为 0。家族不一致的写法本身就是特征。
const COMMON_FONTS = [
  'arial', 'verdana', 'tahoma', 'trebuchet ms', 'times new roman', 'georgia',
  'courier new', 'microsoft yahei', 'simsun', 'meiryo', 'ms gothic',
  'helvetica', 'impact', 'comic sans ms', 'consolas',
];
function makePlugins() {
  const specs = [
    ['Chrome PDF Plugin', 'internal-pdf-viewer', 'Portable Document Format'],
    ['Chrome PDF Viewer', 'mhjfbmdgcfjbbpaeojofohoefgiehjai', 'Portable Document Format'],
    ['Native Client', 'internal-nacl-plugin', 'Native Client Executable'],
  ];
  const out = {};
  specs.forEach(([name, filename, description], i) => {
    out[i] = {
      name, filename, description, length: 1,
      item() { return null; }, namedItem() { return null; },
    };
  });
  out.length = specs.length;
  return out;
}
function makeMimeTypes() {
  const specs = [
    ['application/pdf', 'pdf', 'Portable Document Format'],
    ['text/pdf', 'pdf', 'Portable Document Format'],
  ];
  const out = {};
  specs.forEach(([type, suffixes, description], i) => {
    out[i] = { type, suffixes, description, enabledPlugin: null };
  });
  out.length = specs.length;
  return out;
}

// Chromium 的 navigator.userAgentData（Client Hints API）。真 Chrome 始终暴露
// brands/mobile/platform，指纹 SDK 会读它；缺了就是协议模拟的硬伤。
function parseSecChBrands(secChUa) {
  const out = [];
  if (!secChUa) return out;
  const re = /"([^"]+)";\s*v="([^"]+)"/g;
  let m;
  while ((m = re.exec(String(secChUa))) !== null) {
    out.push({ brand: m[1], version: m[2] });
  }
  return out;
}
const uaDataBrands = parseSecChBrands(input.sec_ch_ua);
const uaDataPlatform = String(input.sec_ch_ua_platform || '').replace(/^"|"$/g, '') || 'Windows';
const uaDataMobile = String(input.sec_ch_ua_mobile || '?0') === '?1';

const targetTz = String(input.timezone || 'UTC');
// 目标时区的本地化名称（如 "Japan Standard Time"）。resolvedOptions() 里
// timeZone 被改写后，timeZoneName 仍是宿主时区名，必须一起替换。
let targetTzName = '';
try {
  targetTzName = new Intl.DateTimeFormat('en-US', {
    timeZone: targetTz,
    timeZoneName: 'long',
  }).resolvedOptions().timeZoneName;
} catch (_) {}
const OrigDTF = Intl.DateTimeFormat;
const PatchedDTF = function (locales, options) {
  const inst = new OrigDTF(locales, options);
  const orig = inst.resolvedOptions.bind(inst);
  inst.resolvedOptions = function () {
    const r = orig();
    r.timeZone = targetTz;
    if ('timeZoneName' in r && targetTzName) r.timeZoneName = targetTzName;
    return r;
  };
  return inst;
};
Object.setPrototypeOf(PatchedDTF, OrigDTF);
PatchedDTF.prototype = OrigDTF.prototype;
PatchedDTF.supportedLocalesOf = OrigDTF.supportedLocalesOf;

// Date.getTimezoneOffset 必须与声明的 IANA 时区一致：宿主进程时区是本地（如
// UTC+8），不修的话 Tokyo 账号会报 -480 而不是 -540，PoW 里与 timezone 字段
// 自相矛盾。用 Node 自带 ICU 按目标时区算偏移。
function offsetMinutesForTimeZone(tz) {
  try {
    const parts = new Intl.DateTimeFormat('en-US', {
      timeZone: tz,
      timeZoneName: 'longOffset',
    }).formatToParts(new Date());
    const name = (parts.find((p) => p.type === 'timeZoneName') || {}).value || '';
    const m = /GMT([+-])(\d{2}):?(\d{2})?/.exec(name);
    if (m) {
      const mins = Number(m[2]) * 60 + Number(m[3] || 0);
      return m[1] === '+' ? -mins : mins;
    }
  } catch (_) {}
  return 0;
}
const targetTzOffset = offsetMinutesForTimeZone(targetTz);
Date.prototype.getTimezoneOffset = function () { return targetTzOffset; };

const navigatorObj = {
  userAgent: String(input.user_agent || 'Mozilla/5.0'),
  language: String(input.language || 'en-US'),
  languages: Array.isArray(input.languages) ? input.languages : ['en-US', 'en'],
  hardwareConcurrency: Number(input.hardware_concurrency || 8),
  platform: navPlatform,
  vendor: navVendor,
  maxTouchPoints: Number(input.max_touch_points || 0),
  webdriver: false,
  onLine: true,
  cookieEnabled: true,
  doNotTrack: null,
  appCodeName: 'Mozilla',
  appName: 'Netscape',
  appVersion: '5.0',
  product: 'Gecko',
  productSub: '20030107',
  vendorSub: '',
  connection: { effectiveType: '4g', rtt: 50, downlink: 10, saveData: false },
  plugins: isChromeFamily ? makePlugins() : { length: 0 },
  mimeTypes: isChromeFamily ? makeMimeTypes() : { length: 0 },
  mediaDevices: { enumerateDevices: async () => [] },
  getBattery: async () => ({ charging: true, chargingTime: 0, dischargingTime: Infinity, level: 1 }),
  sendBeacon: () => true,
  permissions: { query: async () => ({ state: 'prompt' }) },
};
if (input.device_memory != null && !Number.isNaN(Number(input.device_memory))) {
  navigatorObj.deviceMemory = Number(input.device_memory);
}
if (uaDataBrands.length) {
  navigatorObj.userAgentData = {
    brands: uaDataBrands,
    mobile: uaDataMobile,
    platform: uaDataPlatform,
    getHighEntropyValues: async () => ({
      architecture: String(input.sec_ch_ua_arch || 'x86'),
      bitness: String(input.sec_ch_ua_bitness || '64'),
      model: String(input.sec_ch_ua_model || ''),
      platform: uaDataPlatform,
      platformVersion: String(input.sec_ch_ua_platform_version || ''),
      fullVersionList: parseSecChBrands(input.sec_ch_ua_full_version_list),
      uaFullVersion: String(input.sec_ch_ua_full_version_list || ''),
    }),
    toJSON() {
      return { brands: uaDataBrands, mobile: uaDataMobile, platform: uaDataPlatform };
    },
  };
}

const cryptoObj = {
  getRandomValues: (arr) => { cryptoMod.randomFillSync(arr); return arr; },
};
if (typeof cryptoMod.randomUUID === 'function') {
  cryptoObj.randomUUID = () => cryptoMod.randomUUID();
}
if (cryptoMod.webcrypto && cryptoMod.webcrypto.subtle) {
  cryptoObj.subtle = cryptoMod.webcrypto.subtle;
}

const context = {
  console,
  setTimeout,
  clearTimeout,
  setInterval,
  clearInterval,
  queueMicrotask,
  Promise,
  URL,
  URLSearchParams,
  Math,
  Date,
  JSON,
  Array,
  Object,
  String,
  Number,
  Boolean,
  RegExp,
  Function,
  Symbol,
  Reflect,
  Proxy,
  Error,
  TypeError,
  RangeError,
  ReferenceError,
  SyntaxError,
  Map,
  Set,
  WeakMap,
  WeakSet,
  Int8Array,
  Uint8Array,
  Uint8ClampedArray,
  Int16Array,
  Uint16Array,
  Int32Array,
  Uint32Array,
  Float32Array,
  Float64Array,
  ArrayBuffer,
  DataView,
  TextEncoder,
  TextDecoder,

  btoa: (s) => Buffer.from(String(s || ''), 'binary').toString('base64'),
  atob: (s) => Buffer.from(String(s || ''), 'base64').toString('binary'),
  unescape,
  encodeURIComponent,
  decodeURIComponent,
  encodeURI,
  decodeURI,
  parseInt,
  parseFloat,
  isFinite,
  isNaN,
  NaN,
  Infinity,
  undefined,
  Intl: { ...Intl, DateTimeFormat: PatchedDTF },

  crypto: cryptoObj,

  performance: {
    // 每号独立的时间锚点与堆上限：timeOrigin 取 Python 侧由 device_id 派生的
    // 过去时刻，now() 按其后的真实流逝时间推进，再叠加每号抖动，避免整批账号
    // 共享同一 timeOrigin / 恒定 4GB 堆的聚类信号。
    now: () => {
      const perfOrigin =
        Number(input.time_origin) > 0 ? Number(input.time_origin) : performance.timeOrigin;
      const perfJitter = Number(input.performance_now) > 0 ? Number(input.performance_now) : 0;
      return Date.now() - perfOrigin + perfJitter;
    },
    timeOrigin:
      Number(input.time_origin) > 0 ? Number(input.time_origin) : performance.timeOrigin,
    memory: {
      jsHeapSizeLimit:
        Number(input.js_heap_size_limit) > 0 ? Number(input.js_heap_size_limit) : 4294967296,
    },
    getEntriesByType: () => [],
    getEntriesByName: () => [],
    mark: () => {},
    measure: () => {},
  },

  screen: {
    width: screenW,
    height: screenH,
    availWidth: screenW,
    // 真桌面浏览器 availHeight 会扣掉任务栏高度，等于 height 是协议模拟特征。
    availHeight: Math.max(0, screenH - 38),
    availTop: 0,
    availLeft: 0,
    colorDepth: 24,
    pixelDepth: 24,
    orientation: { type: 'landscape-primary', angle: 0 },
  },

  navigator: navigatorObj,

  history: {
    length: 1, state: null,
    back() {}, forward() {}, go() {},
    pushState() {}, replaceState() {},
  },

  localStorage: createStorage(),
  sessionStorage: createStorage(),

  innerWidth: screenW,
  innerHeight: screenH,
  outerWidth: screenW,
  outerHeight: screenH + 88,
  screenX: 0,
  screenY: 0,
  screenLeft: 0,
  screenTop: 0,
  devicePixelRatio: Number(input.device_pixel_ratio || 1),
  scrollX: 0,
  scrollY: 0,
  pageXOffset: 0,
  pageYOffset: 0,

  requestAnimationFrame: (cb) => { setTimeout(cb, 16); return 1; },
  cancelAnimationFrame: () => {},
  requestIdleCallback: (cb) => {
    if (typeof cb === 'function') cb({ didTimeout: false, timeRemaining: () => 50 });
    return 1;
  },
  cancelIdleCallback: () => {},

  getComputedStyle: () => ({ getPropertyValue() { return ''; } }),
  matchMedia: (query) => ({
    media: String(query || ''),
    matches: false,
    onchange: null,
    addListener() {}, removeListener() {},
    addEventListener() {}, removeEventListener() {},
    dispatchEvent() { return false; },
  }),

  Event: class Event {
    constructor(type, init) {
      this.type = type;
      this.bubbles = (init && init.bubbles) || false;
      this.cancelable = (init && init.cancelable) || false;
    }
  },
  CustomEvent: class CustomEvent {
    constructor(type, init) {
      this.type = type;
      this.detail = init && Object.prototype.hasOwnProperty.call(init, 'detail') ? init.detail : null;
    }
  },
  MessageChannel: class MessageChannel {
    constructor() {
      this.port1 = { postMessage() {}, addEventListener() {}, removeEventListener() {}, start() {}, close() {} };
      this.port2 = { postMessage() {}, addEventListener() {}, removeEventListener() {}, start() {}, close() {} };
    }
  },

  ...(isChromeFamily ? {
    chrome: {
      runtime: {}, app: {},
      loadTimes() {
        const now = Date.now() / 1000;
        return {
          commitLoadTime: now, connectionInfo: 'http/2',
          finishDocumentLoadTime: now, finishLoadTime: now,
          firstPaintAfterLoadTime: 0, firstPaintTime: 0,
          navigationType: 'Other', npnNegotiatedProtocol: 'h2',
          requestTime: now, startLoadTime: now,
          wasAlternateProtocolAvailable: false, wasFetchedViaSpdy: true,
          wasNpnNegotiated: false,
        };
      },
      csi() { return { startE: 0, onloadT: 0, pageT: 120, tran: 10 }; },
    },
  } : {}),
  CSS: { supports() { return true; } },
  indexedDB: {
    open() { return { onerror: null, onsuccess: null, onupgradeneeded: null, result: {}, error: null }; },
    deleteDatabase() { return {}; },
  },

  fetch: async () => { throw new Error('fetch should not be called'); },
  postMessage: () => {},

  AudioContext: makeAudioContext,
  webkitAudioContext: makeAudioContext,
  OfflineAudioContext: function (channels, length, rate) {
    const ctx = makeAudioContext();
    ctx.length = Number(length) > 0 ? Number(length) : 44100;
    ctx.startRendering = async () => makeAudioBuffer(ctx.length);
    return ctx;
  },

  addEventListener: addListener,
  removeEventListener: removeListener,
  dispatchEvent: (event) => { dispatch(event.type, event); return true; },

  origin: 'https://auth.openai.com',

  location: {
    href: 'https://auth.openai.com/',
    origin: 'https://auth.openai.com',
    protocol: 'https:',
    host: 'auth.openai.com',
    hostname: 'auth.openai.com',
    pathname: '/',
    search: '',
    hash: '',
    assign() {},
    replace() {},
    reload() {},
  },

  document: {
    readyState: 'complete',
    hidden: false,
    visibilityState: 'visible',
    referrer: 'https://auth.openai.com/',
    URL: 'https://auth.openai.com/',
    documentURI: 'https://auth.openai.com/',
    location: {
      href: 'https://auth.openai.com/',
      origin: 'https://auth.openai.com',
      pathname: '/',
      search: '',
    },
    cookie: 'oai-did=' + encodeURIComponent(input.device_id || ''),
    title: '',
    characterSet: 'UTF-8',
    contentType: 'text/html',
    fonts: {
      status: 'loaded',
      size: COMMON_FONTS.length,
      check(f) {
        const q = String(f || '').toLowerCase();
        return COMMON_FONTS.some((x) => q.includes(x));
      },
      has() { return true; },
      add() {}, delete() {}, clear() {}, forEach() {},
      values() { return []; },
      ready: Promise.resolve({}),
    },
    scripts,
    currentScript: {
      src: 'https://sentinel.openai.com/sentinel/sdk.js',
      getAttribute() { return null; },
    },
    documentElement,
    body: bodyEl,
    head: genericElement('head'),
    createElement(tag) {
      const t = String(tag || '').toLowerCase();
      if (t === 'canvas') return canvasElement();
      if (t === 'iframe') {
        iframeObject = genericElement('iframe');
        iframeObject._load = [];
        iframeObject.addEventListener = (type, cb) => {
          if (type === 'load') iframeObject._load.push(cb);
        };
        iframeObject.removeEventListener = () => {};
        iframeObject.contentWindow = {
          postMessage(message, origin) {
            capturedProof = message.p;
            const result = input.action === 'solve'
              ? { cachedChatReq: input.challenge, cachedProof: input.request_p || message.p }
              : null;
            const ev = {
              source: iframeObject.contentWindow,
              data: { type: 'response', requestId: message.requestId, result },
              origin,
            };
            setTimeout(() => {
              for (const cb of [...(_listeners.get('message') || [])]) {
                try { cb(ev); } catch (_) {}
              }
            }, 0);
          },
        };
        return iframeObject;
      }
      const el = genericElement(tag);
      if (t === 'script') scripts.push(el);
      return el;
    },
    createElementNS(_ns, tag) { return this.createElement(tag); },
    createDocumentFragment() { return genericElement('fragment'); },
    createTextNode(text) { return { nodeType: 3, textContent: text }; },
    createComment(text) { return { nodeType: 8, textContent: text }; },
    querySelector() { return null; },
    querySelectorAll() { return []; },
    getElementById() { return null; },
    getElementsByTagName(tag) { return tag === 'script' ? scripts : []; },
    getElementsByClassName() { return []; },
    addEventListener: addListener,
    removeEventListener: removeListener,
    dispatchEvent(event) { dispatch(event.type, event); return true; },
  },
};

// ── 浏览器家族一致性：requirements token 里被加密编码的家族判据 ──────────
// 真机实测（Chrome 153 / Windows，见地面真值探测）：
//   "ai" in window = false，"cache" in window = false，"createPRNG"/"dump"/
//   "InstallTrigger" in window = false —— Chrome 七个布尔全 false。
// Firefox 恒有 createPRNG / dump / InstallTrigger；Safari(WebKit) 恒有 dump。
// 此前 JS VM 一律不定义这些全局，Chrome 分支恰好与真机一致，但 Firefox/
// Safari 分支会交出"任何真实浏览器都不存在"的全 0 组合。
const isFirefoxFamily = browserType === 'firefox';
const isSafariFamily = /safari/i.test(String(browserType || ''));
if (isFirefoxFamily) {
  context.createPRNG = function createPRNG() {};
  context.dump = function dump() {};
  context.InstallTrigger = {};
} else if (isSafariFamily) {
  context.dump = function dump() {};
}

// Navigator.prototype 键集（真机 Chrome 153 实测 95 键 + Firefox/Safari 特有键）。
// sdk.js 的 P() 会随机取一个原型键名再 .toString()；裸 Object.prototype
// 只能交出 constructor/hasOwnProperty 之类，任何真浏览器都不会出现。
const NAV_PROTO_NAMES = [
  'adAuctionComponents', 'appCodeName', 'appName', 'appVersion', 'bluetooth',
  'buildID', 'canLoadAdAuctionFencedFrame', 'canShare', 'clearAppBadge',
  'clearOriginJoinedAdInterestGroups', 'clipboard', 'connection', 'cookieEnabled',
  'cpuPerformance', 'createAuctionNonce', 'credentials', 'deprecatedReplaceInURN',
  'deprecatedRunAdAuctionEnforcesKAnonymity', 'deprecatedURNToURL', 'deviceMemory',
  'devicePosture', 'doNotTrack', 'geolocation', 'getBattery', 'getGamepads',
  'getInstalledRelatedApps', 'getInterestGroupAdAuctionData', 'getUserMedia',
  'globalPrivacyControl', 'gpu', 'hardwareConcurrency', 'hid', 'ink', 'javaEnabled',
  'joinAdInterestGroup', 'keyboard', 'language', 'languages', 'leaveAdInterestGroup',
  'locks', 'login', 'managed', 'maxTouchPoints', 'mediaCapabilities', 'mediaDevices',
  'mediaSession', 'mimeTypes', 'mozGetUserMedia', 'onLine', 'oscpu',
  'pdfViewerEnabled', 'permissions', 'platform', 'plugins', 'presentation',
  'product', 'productSub', 'protectedAudience', 'registerProtocolHandler',
  'requestMIDIAccess', 'requestMediaKeySystemAccess', 'runAdAuction', 'scheduling',
  'sendBeacon', 'serial', 'serviceWorker', 'setAppBadge', 'share', 'storage',
  'storageBuckets', 'taintEnabled', 'unregisterProtocolHandler',
  'updateAdInterestGroups', 'usb', 'userActivation', 'userAgent', 'userAgentData',
  'vendor', 'vendorSub', 'vibrate', 'virtualKeyboard', 'wakeLock', 'webdriver',
  'webkitGetUserMedia', 'webkitPersistentStorage', 'webkitTemporaryStorage',
  'windowControlsOverlay', 'xr',
];
const navProto = {};
for (const name of NAV_PROTO_NAMES) {
  navProto[name] = Object.prototype.hasOwnProperty.call(navigatorObj, name)
    ? navigatorObj[name]
    : undefined;
}
Object.setPrototypeOf(navigatorObj, navProto);

// 真机 Object.keys(document) 恒等于 ["location"]（其余全在 Document.prototype）。
// 此前把 readyState/body/scripts 等 30 个键全部做成自有可枚举键，sdk.js 随机
// 取样时会出现真机永远取不到的名字。
for (const docKey of Object.keys(context.document)) {
  Object.defineProperty(context.document, docKey, { enumerable: false, configurable: true, writable: true });
}
Object.defineProperty(context.document, 'location', { enumerable: true, configurable: true, writable: true });

// window 自身可枚举键集补齐：sdk.js 会随机取一个 Object.keys(window) 的名字。
// 补上真浏览器常驻全局名（值为 undefined 即可，SDK 只取样名字，不调用）。
const EXTRA_WINDOW_GLOBALS = [
  'alert', 'confirm', 'prompt', 'print', 'stop', 'close', 'focus', 'blur', 'open',
  'scroll', 'scrollTo', 'scrollBy', 'moveTo', 'moveBy', 'resizeTo', 'resizeBy',
  'getSelection', 'find', 'frames', 'opener', 'name', 'status', 'closed',
  'customElements', 'trustedTypes', 'scheduler', 'visualViewport', 'speechSynthesis',
  'XMLHttpRequest', 'WebSocket', 'Worker', 'SharedWorker', 'Image', 'Audio',
  'Option', 'DOMParser', 'MutationObserver', 'IntersectionObserver',
  'ResizeObserver', 'PerformanceObserver', 'ReportingObserver', 'EventSource',
  'BroadcastChannel', 'MessagePort', 'ReadableStream', 'WritableStream',
  'TransformStream', 'CompressionStream', 'DecompressionStream', 'AbortController',
  'AbortSignal', 'Blob', 'File', 'FileReader', 'FileList', 'FormData', 'Headers',
  'Request', 'Response', 'WebAssembly', 'Atomics', 'SharedArrayBuffer', 'BigInt',
  'BigInt64Array', 'BigUint64Array', 'WeakRef', 'FinalizationRegistry',
  'AggregateError', 'EvalError', 'URIError', 'structuredClone', 'caches',
  'CrossOriginIsolated', 'isSecureContext', 'origin', 'EventTarget', 'Node',
  'NodeList', 'Element', 'HTMLElement', 'HTMLDivElement', 'HTMLAnchorElement',
  'HTMLButtonElement', 'HTMLFormElement', 'HTMLInputElement', 'HTMLSelectElement',
  'HTMLTextAreaElement', 'HTMLCanvasElement', 'HTMLImageElement', 'HTMLScriptElement',
  'HTMLIFrameElement', 'HTMLStyleElement', 'HTMLLinkElement', 'Document', 'Window',
  'Navigator', 'Screen', 'History', 'Location', 'CSSStyleDeclaration',
  'CSSStyleSheet', 'MediaQueryList', 'DOMException', 'DOMRect', 'DOMPoint',
  'DOMMatrix', 'ImageData', 'Path2D', 'OffscreenCanvas', 'CanvasRenderingContext2D',
  'Touch', 'TouchEvent', 'PointerEvent', 'MouseEvent', 'KeyboardEvent',
  'WheelEvent', 'FocusEvent', 'InputEvent', 'CompositionEvent', 'UIEvent',
  'ProgressEvent', 'ErrorEvent', 'CloseEvent', 'StorageEvent', 'PopStateEvent',
  'HashChangeEvent', 'PageTransitionEvent', 'SubmitEvent', 'DragEvent',
  'ClipboardEvent', 'MessageEvent', 'Notification', 'HTMLAudioElement',
  'HTMLVideoElement', 'HTMLTableElement', 'HTMLTemplateElement', 'ShadowRoot',
];
for (const extraName of EXTRA_WINDOW_GLOBALS) {
  if (!(extraName in context)) {
    Object.defineProperty(context, extraName, {
      value: undefined, enumerable: true, configurable: true, writable: true,
    });
  }
}

context.window = context;
context.globalThis = context;
context.self = context;
context.top = context;
context.parent = context;

// ─── Create VM sandbox & load SDK ──────────────────────────────

vm.createContext(context);
vm.runInContext(sdk, context, { timeout: 10000 });

// ─── Behavior simulation ──────────────────────────────────────

function _rng(min, max) {
  return min + Math.floor(Math.random() * Math.max(1, max - min + 1));
}

async function dispatchBehavior(durationMs) {
  const started = Date.now();
  const moves = _rng(12, 16);
  let x = _rng(260, 420);
  let y = _rng(180, 300);
  for (let i = 0; i < moves; i++) {
    const dx = _rng(5, 18);
    const dy = _rng(-4, 12);
    x += dx;
    y += dy;
    await new Promise(r => setTimeout(r, _rng(70, 145)));
    await dispatch('pointermove', {
      clientX: x, clientY: y, screenX: x, screenY: y,
      movementX: dx, movementY: dy, buttons: 0,
    });
  }
  await new Promise(r => setTimeout(r, _rng(90, 220)));
  await dispatch('click', {
    clientX: x, clientY: y, screenX: x, screenY: y, button: 0, buttons: 0,
  });
  for (let i = 0; i < _rng(3, 4); i++) {
    await new Promise(r => setTimeout(r, _rng(80, 180)));
    context.scrollY = (context.scrollY || 0) + _rng(35, 120);
    context.pageYOffset = context.scrollY;
    await dispatch('scroll', { scrollX: 0, scrollY: context.scrollY });
  }
  await new Promise(r => setTimeout(r, _rng(80, 160)));
  await dispatch('wheel', {
    deltaX: 0, deltaY: _rng(70, 140), clientX: x, clientY: y,
  });
  const keys = ['L', 'u', 'Tab'];
  for (const key of keys) {
    await new Promise(r => setTimeout(r, _rng(90, 210)));
    await dispatch('keydown', {
      key,
      code: key === 'Tab' ? 'Tab' : 'Key' + key.toUpperCase(),
      repeat: false, altKey: false, ctrlKey: false, metaKey: false,
    });
  }
  const remaining = Math.max(0, Number(durationMs || 0) - (Date.now() - started));
  if (remaining > 0) await new Promise(r => setTimeout(r, remaining));
}

// ─── Main ──────────────────────────────────────────────────────

(async () => {
  const action = input.action;
  const flow = String(input.flow || 'authorize_continue');

  if (action === 'requirements') {
    try {
      await Promise.race([
        context.SentinelSDK.init(flow),
        new Promise((_, rej) => setTimeout(() => rej(new Error('init timeout')), 8000)),
      ]);
      if (capturedProof) {
        process.stdout.write(JSON.stringify({ request_p: capturedProof }));
        return;
      }
    } catch (_) {}
    const requestP = await context.__debugP.getRequirementsToken();
    process.stdout.write(JSON.stringify({ request_p: requestP }));
    return;
  }

  if (action === 'solve') {
    const behaviorMs = Number(input.behavior_duration_ms || 4200);

    try {
      const mainToken = await Promise.race([
        context.SentinelSDK.token(flow),
        new Promise((_, rej) => setTimeout(() => rej(new Error('SDK token timeout')), 8000)),
      ]);
      if (mainToken) {
        await dispatchBehavior(behaviorMs);
        let soToken = '';
        try {
          soToken = await Promise.race([
            context.SentinelSDK.sessionObserverToken(flow),
            new Promise((_, rej) => setTimeout(() => rej(new Error('SO timeout')), 5000)),
          ]);
        } catch (_) {
          soToken = '';
        }
        process.stdout.write(JSON.stringify({ token: mainToken, so_token: soToken || '' }));
        return;
      }
    } catch (_) {}

    const challenge = input.challenge || {};
    const requestP = String(input.request_p || '').trim();
    if (!requestP) throw new Error('missing request_p');
    const finalP = await context.__debugP.getEnforcementToken(challenge);
    context.SentinelSDK.__debug_bindProof(challenge, requestP);
    const dx = challenge && challenge.turnstile ? challenge.turnstile.dx : null;
    const tValue = dx ? await context.SentinelSDK.__debug_n(challenge, dx) : null;
    process.stdout.write(JSON.stringify({ final_p: finalP, t: tValue, so_token: '' }));
    return;
  }

  throw new Error('unsupported action: ' + action);
})().catch(err => {
  process.stderr.write(String((err && err.stack) || err));
  process.exit(1);
});
